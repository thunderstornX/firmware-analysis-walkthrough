# Replication steps

End-to-end script for reproducing the findings in this repository
against the OpenWRT 22.03.7 image under `samples/`.

Each step writes its outputs into `results/` so you can diff them
against the committed copy.

---

## 0. Activate the environment

```
source .venv/bin/activate
export JAVA_HOME=$HOME/.local/share/jdk-21
export GHIDRA_INSTALL_DIR=$HOME/.local/share/ghidra
export PATH=$JAVA_HOME/bin:$PATH
```

(Steps 1–3 do not need Ghidra; step 4 does.)

## 1. Extract the rootfs

```
bash scripts/extract.sh
```

* Locates the SquashFS signature with `binwalk`.
* Carves the offset out with `dd`.
* Unpacks the rootfs with `unsquashfs` into `work/squashfs-root/`.

Expected on the bundled image:

* binwalk reports a SquashFS magic at offset **2228344**.
* `unsquashfs` recovers **1371 inodes** (1046 files + 122 dirs + 203
  symlinks).
* `work/squashfs-root/etc/openwrt_release` reads `DISTRIB_RELEASE='22.03.7'`.

## 2. Filesystem enumeration

```
python scripts/enumerate.py
```

Outputs into `results/`:

* `filesystem_tree.txt` — depth-capped tree of the rootfs.
* `firmwalker.txt` — verbatim upstream firmwalker scan (~13.8 KB).
* `pattern_hits.json` — 23 hits across 4 categories on this image:

  | Category | Hits |
  |---|---:|
  | `password_assignment` | 1 |
  | `openssl_invocation` | 1 |
  | `hardcoded_url_http` | 20 |
  | `root_passwd_blank` | 1 |

## 3. Dependency / CVE correlation

```
python scripts/cve_correlate.py
```

* Parses `usr/lib/opkg/status` → 144 packages.
* Writes `results/dependency_versions.csv` (full inventory).
* Queries NVD 2.0 for the **9 packages** with a known
  vendor/product mapping (busybox, dnsmasq, openssl variants,
  curl/libcurl, hostapd/wpad family, kernel, ppp, samba). The NVD
  cool-down means this step takes ~1 minute on the first run; the
  `.nvd_cache/` directory makes subsequent runs instant.
* Writes `results/findings.md` (severity-grouped) and
  `results/cve_correlate.json` (machine-readable).

Expected total: **16 CVE matches** — 8 critical, 5 high, 2 medium,
1 low. The critical CVEs are the six dnsmasq heap overflows
(`CVE-2021-45951..45956`), the busybox shell stack overflow
(`CVE-2022-48174`), and one cluster around the kernel/libcurl
mapping.

To pass an NVD API key (raises the rate limit from 5→50 req/30s):

```
export NVD_API_KEY=...
python scripts/cve_correlate.py
```

## 4. Binary analysis (Ghidra 12 / PyGhidra)

```
bash scripts/run_ghidra.sh work/squashfs-root/bin/busybox 1500
```

* Imports the **323 KiB MIPS** busybox binary into a throwaway
  Ghidra project.
* Runs the headless `scripts/ghidra_script.py` post-script.
* Writes `results/ghidra_report.json`.

Expected on this image:

| Field | Count |
|---|---:|
| `imports` | 328 |
| `exports` | 20 |
| `suspicious_xrefs` (categories) | 13 |
| `suspicious_xrefs` (total call-sites) | 256 |
| `strings` | 500 (capped) |

`suspicious_xrefs` walks every program function, identifies thunks
to the named external functions (`system`, `popen`, `execve`,
`execvp`, `execl`, `execlp`, `strcpy`, `strcat`, `sprintf`,
`memcpy`, `setuid`, `setgid`, `seteuid`), and records each unique
in-binary call-site. The heaviest signal on busybox is — as
expected — `memcpy` (112 sites) and `strcpy` (79 sites).

The 1500 MiB heap cap is plenty for busybox; bump it for larger
binaries (`bash scripts/run_ghidra.sh <binary> 3000`).

## 5. Re-run the DevSecOps gates

```
bandit  -r scripts/
pip-audit -r requirements.txt
semgrep --config p/python --config p/security-audit scripts/ tests/
hadolint docker/Dockerfile
shellcheck scripts/extract.sh scripts/run_ghidra.sh docker/install_ghidra.sh
```

All gates should be clean. See `results/security_scan.md` for the
frozen snapshot.

## 6. Tests

```
pytest tests/ -q
```

22 tests covering: opkg parser, version normaliser, CPE formatter,
NVD client (mocked, with cache + 404 + API-key paths), severity
extraction, findings-markdown rendering, pattern scanner, text-file
walker, and tree renderer.
