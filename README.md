```
   __ _                                                        _           _
  / _(_)                                                      | |         (_)
 | |_ _ _ __ _ __ ___  __      ____ _ _ __ ___    __ _ _ __   ___| |_   _ ___ ___
 |  _| | '__| '_ ` _ \ \ \ /\ / / _` | '__/ _ \  / _` | '_ \ / _ \ | | | / __/ __|
 | | | | |  | | | | | | \ V  V / (_| | | |  __/ | (_| | | | |  __/ | |_| \__ \__ \
 |_| |_|_|  |_| |_| |_|  \_/\_/ \__,_|_|  \___|  \__,_|_| |_|\___|_|\__, |___/___/
                                                                     __/ |
                              walkthrough                            |___/
```

# firmware-analysis-walkthrough

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20480608.svg)](https://doi.org/10.5281/zenodo.20480608)

A reproducible firmware-security pipeline applied to OpenWRT 22.03.7
on the TP-Link Archer C7 v2 (`ath79` / `mips_24kc`). One firmware
blob in, four scripts later, a directory full of evidence comes
out — every byte content-addressed and every artefact committed.

| Stage | Script | Output |
|---|---|---|
| 1. Extract SquashFS | `scripts/extract.sh` | `work/squashfs-root/` |
| 2. Filesystem enumeration | `scripts/enumerate.py` | `results/filesystem_tree.txt`, `firmwalker.txt`, `pattern_hits.json` |
| 3. Dependency / CVE correlation | `scripts/cve_correlate.py` | `results/dependency_versions.csv`, `findings.md`, `cve_correlate.json` |
| 4. Headless Ghidra analysis | `scripts/run_ghidra.sh` | `results/ghidra_report.json` |

## What this pipeline produces on the bundled sample

The OpenWRT 22.03.7 release image for the Archer C7 v2 is committed
under `samples/` (SHA-256
`0ca4fe70efe20208bc32b7d636f58226e9f1a872d279dc6a3d05b0f99b677713`,
6{,}488{,}389 bytes). On that image, an end-to-end run produces:

* **1371 inodes** extracted from SquashFS (1046 files / 122 dirs / 203 symlinks).
* **144 packages** parsed from the opkg status manifest.
* **16 NVD-confirmed CVEs** across 9 mapped components — 8 Critical, 5 High, 2 Medium, 1 Low.
  The Critical cluster is led by the seven dnsmasq heap overflows
  (`CVE-2021-45951..45957`) and busybox's `CVE-2022-48174`.
* **23 filesystem pattern hits** across 4 categories
  (`password_assignment`, `openssl_invocation`,
  `hardcoded_url_http`, `root_passwd_blank`).
* **328 imports**, **20 exports**, **256 suspicious in-binary call sites** across
  13 libc families (`memcpy`, `strcpy`, `sprintf`, `system`,
  `popen`, the `exec*` family, the `set?id` family), and **500 strings**
  recovered from the 323 KiB MIPS busybox binary at `bin/busybox`.

All of the above are committed under `results/`. If you re-run the
pipeline you should reproduce them byte-for-byte (modulo NVD
publishing new entries against the same CPEs).

## Quick start

```bash
# 1. Environment (see docs/setup_guide.md for tools + Ghidra)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Extract → enumerate → correlate
bash   scripts/extract.sh
python scripts/enumerate.py
python scripts/cve_correlate.py

# 3. (optional) Ghidra binary analysis
export JAVA_HOME=$HOME/.local/share/jdk-21
export GHIDRA_INSTALL_DIR=$HOME/.local/share/ghidra
export PATH=$JAVA_HOME/bin:$PATH
bash scripts/run_ghidra.sh work/squashfs-root/bin/busybox 1500
```

The CVE step honours NVD's 6-second cool-down; expect ≈1 minute on a
cold cache and instantaneous afterwards.

## Repository layout

```
samples/      firmware images, SHA-256-pinned in this README
scripts/      the four pipeline stages
results/      committed artefacts of the live run
tests/        pytest suite (22 cases) covering parser, regexes, NVD client
docs/         setup_guide.md + replication_steps.md
docker/       hermetic analysis image + optional Ghidra installer
paper/        IEEE-format short paper describing the methodology
```

## Tests

```
source .venv/bin/activate
pytest tests/ -q
```

The suite is hermetic — the NVD client is exercised through
mocked HTTP responses — so it runs offline in a fraction of a
second.

## DevSecOps gates

The repository passes the following gates with zero findings (see
`results/security_scan.md`):

* **bandit** on `scripts/` (two `nosec` annotations on the
  intentional subprocess use that drives firmwalker).
* **pip-audit** on `requirements.txt`.
* **semgrep** with `p/python` + `p/security-audit`.
* **hadolint** on `docker/Dockerfile`.
* **shellcheck** on every shell script.

## Container

```
docker build -t firmware-analysis -f docker/Dockerfile .
docker run --rm -it -v "$PWD":/work firmware-analysis
```

The image bundles `binwalk` (Rust 3.1.0), `unsquashfs`, firmwalker,
and the project's Python dependencies. Ghidra is *not* included
(it would inflate the image past 500 MiB); run
`bash docker/install_ghidra.sh` inside the container if you want
the binary-analysis leg.

## Paper

`paper/paper.pdf` is a 3-page IEEE-format short paper describing
the methodology and the numbers above. Build with `pdflatex` if
you want to regenerate it.

## License

MIT. Firmware sample under `samples/` is the unmodified OpenWRT
release artefact and remains subject to its upstream licence.

## Ethical use

This repository analyses a firmware image that the original vendor
publishes for free download. Apply the same techniques to firmware
you have a right to test. Read `ETHICAL_USE.md` if that line is
fuzzy for you.
