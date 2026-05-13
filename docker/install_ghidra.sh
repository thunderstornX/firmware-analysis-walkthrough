#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# install_ghidra.sh — opt-in installer for Ghidra 12 + Temurin JDK
# 21 inside the analysis container (or on a host).
#
# Bundling Ghidra into the base image would add ~500 MiB and pull
# in a JDK; most users running the lighter extract/enumerate/CVE
# legs do not need it. Run this once after `docker run` to set up
# the binary-analysis tooling.
#
#   bash docker/install_ghidra.sh
#
# Honours GHIDRA_VERSION / GHIDRA_BUILD_DATE / JDK_VERSION envs.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

: "${GHIDRA_VERSION:=12.0.4_PUBLIC}"
: "${GHIDRA_BUILD_DATE:=20251015}"
: "${JDK_VERSION:=21.0.5+11}"

INSTALL_ROOT="${INSTALL_ROOT:-${HOME}/.local/share}"
mkdir -p "${INSTALL_ROOT}"

GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION%_PUBLIC}_build/ghidra_${GHIDRA_VERSION}_${GHIDRA_BUILD_DATE}.zip"
JDK_URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${JDK_VERSION/+/%2B}/OpenJDK21U-jdk_x64_linux_hotspot_${JDK_VERSION/+/_}.tar.gz"

# ─── JDK ──────────────────────────────────────────────────────────
if [[ ! -d "${INSTALL_ROOT}/jdk-21" ]]; then
  echo "[install_ghidra] fetching Temurin JDK ${JDK_VERSION}"
  curl -L --fail --silent --show-error -o /tmp/jdk21.tar.gz "${JDK_URL}"
  tar -xzf /tmp/jdk21.tar.gz -C "${INSTALL_ROOT}"
  mv "${INSTALL_ROOT}"/jdk-21.* "${INSTALL_ROOT}/jdk-21" 2>/dev/null || true
  rm /tmp/jdk21.tar.gz
fi

# ─── Ghidra ──────────────────────────────────────────────────────
if [[ ! -d "${INSTALL_ROOT}/ghidra" ]]; then
  echo "[install_ghidra] fetching Ghidra ${GHIDRA_VERSION}"
  curl -L --fail --silent --show-error -o /tmp/ghidra.zip "${GHIDRA_URL}"
  unzip -q /tmp/ghidra.zip -d "${INSTALL_ROOT}"
  mv "${INSTALL_ROOT}"/ghidra_"${GHIDRA_VERSION}"_* "${INSTALL_ROOT}/ghidra"
  rm /tmp/ghidra.zip
fi

# ─── PyGhidra into the active venv (or user site) ────────────────
export JAVA_HOME="${INSTALL_ROOT}/jdk-21"
export PATH="${JAVA_HOME}/bin:${PATH}"
WHEEL="${INSTALL_ROOT}/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.0.2-py3-none-any.whl"
if [[ -f "${WHEEL}" ]]; then
  echo "[install_ghidra] installing PyGhidra"
  pip install --no-cache-dir "${WHEEL}"
fi

echo
echo "[install_ghidra] done."
echo "  JDK_HOME    = ${INSTALL_ROOT}/jdk-21"
echo "  GHIDRA_HOME = ${INSTALL_ROOT}/ghidra"
echo
echo "  export JAVA_HOME=${INSTALL_ROOT}/jdk-21"
echo "  export PATH=\$JAVA_HOME/bin:\$PATH"
echo "  bash scripts/run_ghidra.sh work/squashfs-root/bin/busybox 1500"
