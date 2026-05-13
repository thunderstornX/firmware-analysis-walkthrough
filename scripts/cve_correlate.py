"""CVE correlator: extract dependency versions from an extracted OpenWRT
rootfs and query the NVD 2.0 API for known CVEs.

The OpenWRT image carries a complete opkg package manifest under
``/usr/lib/opkg/status``; we parse it for ``Package``, ``Version``,
and ``Section`` triples and feed each into the NVD ``cpeMatchString``
endpoint. Results are cached locally so repeat runs are
deterministic and do not hammer the NVD service.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import requests

REPO   = Path(__file__).resolve().parent.parent
WORK   = REPO / "work"
ROOT   = WORK / "squashfs-root"
OUT    = REPO / "results"
CACHE  = REPO / ".nvd_cache"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map opkg package names to NVD-side product names where they differ.
# Conservative — we only map cases where the upstream NVD entry is
# clearly under a different product name.
PACKAGE_TO_NVD_PRODUCT: dict[str, tuple[str, str]] = {
    # opkg_name : (vendor, product)
    "busybox":        ("busybox",          "busybox"),
    "dropbear":       ("dropbear_ssh_project", "dropbear_ssh"),
    "openssl":        ("openssl",          "openssl"),
    "libopenssl":     ("openssl",          "openssl"),
    "libopenssl1.1":  ("openssl",          "openssl"),
    "libssl1.1":      ("openssl",          "openssl"),
    "uhttpd":         ("openwrt",          "uhttpd"),
    "wpad":           ("w1.fi",            "hostapd"),
    "wpad-basic":     ("w1.fi",            "hostapd"),
    "wpad-mini":      ("w1.fi",            "hostapd"),
    "wpad-basic-wolfssl": ("w1.fi",        "hostapd"),
    "hostapd":        ("w1.fi",            "hostapd"),
    "hostapd-common": ("w1.fi",            "hostapd"),
    "dnsmasq":        ("thekelleys",       "dnsmasq"),
    "dnsmasq-full":   ("thekelleys",       "dnsmasq"),
    "curl":           ("haxx",             "curl"),
    "libcurl":        ("haxx",             "curl"),
    "kernel":         ("linux",            "linux_kernel"),
    "ppp":            ("paul_mackerras",   "point-to-point_protocol"),
    "samba4-server":  ("samba",            "samba"),
}

SEVERITY_BANDS = ("critical", "high", "medium", "low", "unknown")


@dataclass
class Package:
    name:    str
    version: str
    section: str | None = None
    cves:    list[dict] = field(default_factory=list)


def _parse_opkg_status(status_file: Path) -> list[Package]:
    """Parse OpenWRT's /usr/lib/opkg/status into Package records."""
    if not status_file.is_file():
        return []
    out: list[Package] = []
    current: dict[str, str] = {}
    for raw in status_file.read_text(errors="replace").splitlines():
        if not raw.strip():
            if current.get("Package") and current.get("Version"):
                out.append(Package(
                    name=current["Package"],
                    version=current["Version"],
                    section=current.get("Section"),
                ))
            current = {}
            continue
        if raw.startswith(" "):
            # Continuation line — ignore for our purposes.
            continue
        if ":" in raw:
            k, _, v = raw.partition(":")
            current[k.strip()] = v.strip()
    # Flush trailing block.
    if current.get("Package") and current.get("Version"):
        out.append(Package(
            name=current["Package"],
            version=current["Version"],
            section=current.get("Section"),
        ))
    return out


def _normalise_version(raw: str) -> str:
    """Strip OpenWRT revision suffixes (``-1``, ``+2024.04.01-1``)."""
    # Drop a trailing ``-N`` revision (OpenWRT packaging revision).
    v = re.sub(r"-r?\d+$", "", raw)
    # Drop a ``+TAG-N`` suffix.
    v = re.sub(r"\+[A-Za-z0-9.]+-?\d*$", "", v)
    return v


def _cpe_match_string(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _cache_key(*parts: str) -> str:
    h = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]
    return h


def _query_nvd(vendor: str, product: str, version: str,
               api_key: str | None,
               cache_dir: Path,
               sleep_seconds: float = 6.0) -> list[dict]:
    """Look up CVEs for a given (vendor, product, version)."""
    cpe = _cpe_match_string(vendor, product, version)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{_cache_key(cpe)}.json"
    if cache_file.is_file():
        return json.loads(cache_file.read_text())

    headers: dict[str, str] = {"User-Agent": "firmware-analysis-walkthrough/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    params = {"cpeName": cpe}
    try:
        resp = requests.get(NVD_API, params=params, headers=headers, timeout=20)
    except requests.RequestException as e:
        print(f"  (nvd: network error for {cpe}: {e})", file=sys.stderr)
        cache_file.write_text("[]")
        return []
    if resp.status_code == 404:
        cache_file.write_text("[]")
        return []
    if resp.status_code != 200:
        print(f"  (nvd: HTTP {resp.status_code} for {cpe})", file=sys.stderr)
        cache_file.write_text("[]")
        return []
    data = resp.json()
    cves: list[dict] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cves.append({
            "id":         cve.get("id"),
            "severity":   _severity_from_metrics(cve.get("metrics", {})),
            "summary":    _english_description(cve.get("descriptions", [])),
            "published":  cve.get("published"),
        })
    cache_file.write_text(json.dumps(cves, indent=2))
    # Honour NVD's 6-second cool-down between unauthenticated requests.
    time.sleep(sleep_seconds)
    return cves


def _severity_from_metrics(metrics: dict) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            severity = (rows[0].get("cvssData") or {}).get("baseSeverity") \
                or rows[0].get("baseSeverity") \
                or ""
            return severity.lower() or "unknown"
    return "unknown"


def _english_description(descs: Iterable[dict]) -> str:
    for d in descs:
        if d.get("lang") == "en":
            return (d.get("value") or "").strip()
    return ""


def _findings_markdown(packages: list[Package]) -> str:
    bands: dict[str, list[tuple[Package, dict]]] = {b: [] for b in SEVERITY_BANDS}
    for pkg in packages:
        for c in pkg.cves:
            bands.setdefault(c.get("severity", "unknown"), []).append((pkg, c))

    out: list[str] = []
    out.append("# CVE correlation findings")
    out.append("")
    out.append("Source firmware: OpenWRT 22.03.7 (ath79/generic, mips_24kc).")
    out.append("")

    total = sum(len(v) for v in bands.values())
    out.append(f"**Total CVE matches:** {total}")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    for b in SEVERITY_BANDS:
        out.append(f"| {b} | {len(bands.get(b, []))} |")
    out.append("")

    for b in SEVERITY_BANDS:
        rows = bands.get(b) or []
        if not rows:
            continue
        out.append(f"## {b.title()} ({len(rows)})")
        out.append("")
        out.append("| Package | Version | CVE | Published | Summary |")
        out.append("|---|---|---|---|---|")
        for pkg, c in sorted(rows, key=lambda x: (x[0].name, x[1].get("id") or "")):
            summary = (c.get("summary") or "").replace("|", "\\|")
            if len(summary) > 120:
                summary = summary[:117] + "…"
            out.append(f"| `{pkg.name}` | `{pkg.version}` | "
                       f"[{c.get('id')}](https://nvd.nist.gov/vuln/detail/{c.get('id')}) | "
                       f"{(c.get('published') or '')[:10]} | {summary} |")
        out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--out",  type=Path, default=OUT)
    ap.add_argument("--cache", type=Path, default=CACHE)
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--limit", type=int, default=0,
                    help="if >0, only query the first N packages "
                         "(useful when iterating without burning quota)")
    ns = ap.parse_args()

    status_file = ns.root / "usr" / "lib" / "opkg" / "status"
    if not status_file.is_file():
        print(f"error: opkg status not found at {status_file}",
              file=sys.stderr)
        print("       run scripts/extract.sh first.", file=sys.stderr)
        return 2

    packages = _parse_opkg_status(status_file)
    print(f"[cve_correlate] parsed {len(packages)} package(s) from opkg status")

    # Write dependency_versions.csv for every package, regardless of
    # whether we look it up in NVD.
    ns.out.mkdir(parents=True, exist_ok=True)
    csv_path = ns.out / "dependency_versions.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["package", "version", "normalised_version", "section",
                    "nvd_vendor", "nvd_product", "queried"])
        for pkg in packages:
            mapped = PACKAGE_TO_NVD_PRODUCT.get(pkg.name)
            w.writerow([pkg.name, pkg.version, _normalise_version(pkg.version),
                        pkg.section or "",
                        mapped[0] if mapped else "",
                        mapped[1] if mapped else "",
                        "yes" if mapped else "no"])
    print(f"[cve_correlate] wrote {csv_path}")

    # Query NVD only for packages with a known mapping.
    targets = [p for p in packages if p.name in PACKAGE_TO_NVD_PRODUCT]
    if ns.limit > 0:
        targets = targets[:ns.limit]
    print(f"[cve_correlate] querying NVD for {len(targets)} mapped package(s)")
    for pkg in targets:
        vendor, product = PACKAGE_TO_NVD_PRODUCT[pkg.name]
        norm = _normalise_version(pkg.version)
        cves = _query_nvd(vendor, product, norm, ns.api_key, ns.cache)
        pkg.cves = cves
        print(f"  {pkg.name:<22} {norm:<20} → {len(cves):>3} CVE(s)")

    findings_md = _findings_markdown(targets)
    (ns.out / "findings.md").write_text(findings_md)
    print(f"[cve_correlate] wrote {ns.out/'findings.md'}")

    # Stable JSON output for downstream / regression checks.
    payload = {
        "firmware": "openwrt-22.03.7-ath79-archer-c7-v2",
        "packages": [
            {"name": p.name, "version": p.version,
             "normalised_version": _normalise_version(p.version),
             "section": p.section,
             "cves": p.cves}
            for p in targets
        ],
    }
    (ns.out / "cve_correlate.json").write_text(json.dumps(payload, indent=2))
    print(f"[cve_correlate] wrote {ns.out/'cve_correlate.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
