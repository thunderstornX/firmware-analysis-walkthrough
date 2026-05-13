"""Filesystem enumeration: firmwalker + curated credential-pattern scan.

Emits, into the results/ directory:

  * ``filesystem_tree.txt`` — the rendered directory tree of the
    extracted rootfs (depth-capped so it does not explode in the
    common case).
  * ``firmwalker.txt``      — the verbatim output of upstream firmwalker.
  * ``pattern_hits.json``   — per-pattern hit list from the curated
    Python-side scanner.
"""
from __future__ import annotations

import argparse
import json
import os
import re
# Used to invoke firmwalker.sh with a fully-controlled argv (no shell).
import subprocess  # nosec B404
import sys
from pathlib import Path

REPO  = Path(__file__).resolve().parent.parent
WORK  = REPO / "work"
ROOT  = WORK / "squashfs-root"
OUT   = REPO / "results"

# ─── patterns we care about ────────────────────────────────────────
# Each pattern is (name, regex, max_results_per_file, glob_filter).
# The glob_filter avoids scanning large binary blobs for text
# patterns that would never match.
TEXT_GLOBS = (
    "*.conf", "*.cfg", "*.ini", "*.json", "*.yaml", "*.yml",
    "*.sh",   "*.lua", "*.py",  "*.js",   "*.html", "*.txt",
    "passwd", "shadow", "group", "*.pem", "*.key", "*.crt",
)

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_header",
     re.compile(r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----")),
    ("password_assignment",
     re.compile(r"(?im)^\s*password\s*[:=]\s*['\"]?[^\s'\"]+", re.IGNORECASE)),
    ("hardcoded_telnet",
     re.compile(r"\btelnet(?:d)?\b", re.IGNORECASE)),
    ("openssl_invocation",
     re.compile(r"\bopenssl\s+(?:enc|aes|s_client|s_server)\b")),
    ("hardcoded_url_http",
     re.compile(r"\bhttp://[a-zA-Z0-9._-]+(?:/[^\s'\"]*)?")),
    ("default_admin_login",
     re.compile(r"\badmin\s*[:=]\s*['\"]?(?:admin|password|1234|root)['\"]?",
                re.IGNORECASE)),
    ("root_passwd_blank",
     re.compile(r"^root::", re.MULTILINE)),
    ("api_token_like",
     re.compile(r"""\b(?:api[_-]?key|api[_-]?token|secret[_-]?key)
                    ['"]?\s*[:=]\s*['"]?
                    [A-Za-z0-9_\-]{16,}""",
                re.IGNORECASE | re.VERBOSE)),
)


def _walk_text_files(root: Path):
    """Yield text-ish files under *root*, capped to a manageable set."""
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for f in files:
            p = Path(dirpath) / f
            # Match against any of the text globs, OR known-no-extension
            # config/key files (passwd, shadow, ...).
            for g in TEXT_GLOBS:
                if p.match(g):
                    yield p
                    break


def _render_tree(root: Path, max_depth: int = 4) -> str:
    out_lines: list[str] = [str(root)]
    root_len = len(root.parts)
    for dirpath, dirs, files in sorted(os.walk(root, followlinks=False)):
        depth = len(Path(dirpath).parts) - root_len
        if depth >= max_depth:
            dirs[:] = []  # do not descend
            continue
        indent = "  " * depth
        rel = Path(dirpath).relative_to(root)
        if str(rel) != ".":
            out_lines.append(f"{indent}{rel.name}/")
        # show files at this depth
        for f in sorted(files):
            out_lines.append(f"{indent}  {f}")
    return "\n".join(out_lines)


def _run_firmwalker(root: Path, firmwalker_script: Path) -> str:
    """Run upstream firmwalker.sh and return its captured stdout+stderr.

    firmwalker.sh references its ``data/`` directory via relative paths,
    so it must be invoked from its own install directory. We copy the
    output back out afterwards.
    """
    if not firmwalker_script.is_file():
        return ("(firmwalker.sh not found at {p}; skipping)\n"
                .format(p=firmwalker_script))
    fw_dir = firmwalker_script.parent
    # firmwalker.sh is an upstream tool we drive intentionally with a
    # fully-controlled argv (no shell, no user-supplied strings) — the
    # bandit shell-execution warnings on the next call do not apply.
    proc = subprocess.run(
        ["bash", str(firmwalker_script), str(root) + "/"],  # nosec
        cwd=str(fw_dir),
        capture_output=True, text=True, timeout=600,
        check=False,
    )
    out = fw_dir / "firmwalker.txt"
    if out.exists():
        return out.read_text(errors="replace")
    return proc.stdout + "\n" + proc.stderr


def _scan_patterns(root: Path) -> dict[str, list[dict]]:
    hits: dict[str, list[dict]] = {name: [] for name, _ in PATTERNS}
    for f in _walk_text_files(root):
        try:
            data = f.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        rel = str(f.relative_to(root))
        for name, regex in PATTERNS:
            for m in regex.finditer(data):
                line_no = data.count("\n", 0, m.start()) + 1
                hits[name].append({
                    "path": rel,
                    "line": line_no,
                    "match": m.group(0)[:120],
                })
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT,
                    help=f"extracted root filesystem (default: {ROOT})")
    ap.add_argument("--firmwalker", type=Path,
                    default=Path.home() / ".local/share/firmwalker/firmwalker.sh",
                    help="path to firmwalker.sh")
    ap.add_argument("--out", type=Path, default=OUT,
                    help="where to write the enumeration outputs")
    ns = ap.parse_args()

    if not ns.root.is_dir():
        print(f"error: extracted root not found: {ns.root}", file=sys.stderr)
        print("       run scripts/extract.sh first.", file=sys.stderr)
        return 2

    ns.out.mkdir(parents=True, exist_ok=True)

    # ─── filesystem tree (depth-capped) ───────────────────────────
    tree = _render_tree(ns.root, max_depth=4)
    (ns.out / "filesystem_tree.txt").write_text(tree + "\n")
    print(f"[enumerate] wrote {ns.out/'filesystem_tree.txt'}")

    # ─── firmwalker ────────────────────────────────────────────────
    fw_out = _run_firmwalker(ns.root, ns.firmwalker)
    (ns.out / "firmwalker.txt").write_text(fw_out)
    print(f"[enumerate] wrote {ns.out/'firmwalker.txt'} "
          f"({len(fw_out)} bytes)")

    # ─── curated patterns ─────────────────────────────────────────
    hits = _scan_patterns(ns.root)
    (ns.out / "pattern_hits.json").write_text(json.dumps(hits, indent=2))
    total = sum(len(v) for v in hits.values())
    nonempty = sum(1 for v in hits.values() if v)
    print(f"[enumerate] wrote {ns.out/'pattern_hits.json'} — "
          f"{total} total match(es) across {nonempty} pattern(s)")

    for name, matches in hits.items():
        print(f"  {name:<22} {len(matches)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
