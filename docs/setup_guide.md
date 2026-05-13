# Setup guide

This guide walks you from a clean Debian-based host to a working
firmware-analysis environment for this repository. The instructions
have been exercised on Ubuntu 24.04 / Linux 6.8 (the host this work
was developed on) and should transpose cleanly to other recent
glibc distributions.

If you prefer not to touch your host, jump to
[Docker](#option-b-docker-only) — there is a hermetic image waiting
for you.

---

## Option A — host install

### 0. System packages

```
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-pip \
    squashfs-tools \
    git curl unzip ca-certificates \
    build-essential pkg-config libfontconfig1-dev
```

`squashfs-tools` is required to unpack OpenWRT root filesystems;
`build-essential` + `pkg-config` + `libfontconfig1-dev` are needed
only to compile the Rust binwalk binary in the next step.

### 1. Python environment

```
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. binwalk 3.x (Rust rewrite)

The PyPI `binwalk` package is unrelated to the upstream firmware
extractor (the name is squatted at version 0.0.1). Install via
cargo instead:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo install binwalk --version 3.1.0
```

The binary lands at `~/.cargo/bin/binwalk` — make sure it is on your
`PATH`.

### 3. firmwalker

```
git clone https://github.com/craigz28/firmwalker.git \
    ~/.local/share/firmwalker
```

The enumeration script invokes `firmwalker.sh` from its install
directory so the tool's relative `data/` references resolve.

### 4. Ghidra 12 + Temurin JDK 21 (optional — for the binary leg)

The Ghidra walkthrough requires Ghidra 12 (PyGhidra, post-Jython)
and a JDK 21 build. Convenience installer:

```
bash docker/install_ghidra.sh
```

Or by hand:

```
# JDK 21
curl -LO https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5+11/OpenJDK21U-jdk_x64_linux_hotspot_21.0.5_11.tar.gz
tar -xzf OpenJDK21U-jdk_x64_linux_hotspot_21.0.5_11.tar.gz -C ~/.local/share/
mv ~/.local/share/jdk-21.* ~/.local/share/jdk-21

# Ghidra 12.0.4
curl -LO https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20251015.zip
unzip ghidra_12.0.4_PUBLIC_20251015.zip -d ~/.local/share/
mv ~/.local/share/ghidra_12.0.4_PUBLIC_* ~/.local/share/ghidra

# PyGhidra (CPython 3 bridge) into the project venv
source .venv/bin/activate
pip install ~/.local/share/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.0.2-py3-none-any.whl
```

Set the environment variables `scripts/run_ghidra.sh` expects:

```
export JAVA_HOME=$HOME/.local/share/jdk-21
export GHIDRA_INSTALL_DIR=$HOME/.local/share/ghidra
export PATH=$JAVA_HOME/bin:$PATH
```

### 5. Sample firmware

A copy of the target image lives under `samples/`. To re-download
it from the OpenWRT mirror:

```
mkdir -p samples
curl -L \
  https://archive.openwrt.org/releases/22.03.7/targets/ath79/generic/openwrt-22.03.7-ath79-generic-tplink_archer-c7-v2-squashfs-factory.bin \
  -o samples/openwrt-22.03.7-ath79-archer-c7-v2.bin
sha256sum samples/openwrt-22.03.7-ath79-archer-c7-v2.bin
# expected: 0ca4fe70efe20208bc32b7d636f58226e9f1a872d279dc6a3d05b0f99b677713
```

---

## Option B — Docker only

```
docker build -t firmware-analysis -f docker/Dockerfile .
docker run --rm -it -v "$PWD":/work firmware-analysis
```

Inside the container you have `binwalk`, `unsquashfs`, `firmwalker`,
and the project's Python dependencies. Ghidra is *not* bundled (it
adds ~500 MiB); run `bash docker/install_ghidra.sh` if you want the
binary-analysis leg too.

---

## Verifying the install

```
source .venv/bin/activate
pytest tests/ -q
```

You should see `22 passed`. The full pipeline takes a few minutes
on first run because the CVE step honours NVD's 6-second per-call
cooldown; later runs read from `.nvd_cache/`.
