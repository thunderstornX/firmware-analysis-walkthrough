#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# extract.sh — binwalk + unsquashfs driven extraction.
#
# Usage:  bash scripts/extract.sh [<firmware.bin>] [<workdir>]
# Defaults: samples/openwrt-22.03.7-ath79-archer-c7-v2.bin  and  ./work
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMG="${1:-${REPO_ROOT}/samples/openwrt-22.03.7-ath79-archer-c7-v2.bin}"
WORK="${2:-${REPO_ROOT}/work}"

if ! command -v binwalk >/dev/null 2>&1; then
  echo "ERROR: 'binwalk' not in PATH. Install via cargo:" >&2
  echo "       cargo install binwalk" >&2
  exit 2
fi
if ! command -v unsquashfs >/dev/null 2>&1; then
  echo "ERROR: 'unsquashfs' not in PATH. Install squashfs-tools." >&2
  exit 3
fi
if [[ ! -f "${IMG}" ]]; then
  echo "ERROR: firmware image '${IMG}' not found." >&2
  exit 4
fi

mkdir -p "${WORK}"

echo "[extract] binwalk -e -M on ${IMG}"
echo "          → ${WORK}/binwalk/"
rm -rf "${WORK}/binwalk"
mkdir -p "${WORK}/binwalk"
binwalk -e -M -C "${WORK}/binwalk" --quiet "${IMG}" 2>/dev/null || true   # binwalk returns non-zero on per-extractor failures even when the scan succeeded
echo

echo "[extract] locate the squashfs offset"
SQUASHFS_OFFSET=$(binwalk "${IMG}" 2>/dev/null | awk '/SquashFS/ { print $1; exit }')
if [[ -z "${SQUASHFS_OFFSET}" ]]; then
  echo "ERROR: no SquashFS signature found in ${IMG}." >&2
  exit 5
fi
echo "          → offset = ${SQUASHFS_OFFSET}"

echo "[extract] carve and unsquashfs"
SQSH="${WORK}/firmware.sqsh"
dd if="${IMG}" of="${SQSH}" bs=1 skip="${SQUASHFS_OFFSET}" status=none

ROOT="${WORK}/squashfs-root"
rm -rf "${ROOT}"
unsquashfs -d "${ROOT}" "${SQSH}" >"${WORK}/unsquashfs.log" 2>&1
INODES=$(awk '/created [0-9]+ files/ { print $2; exit }' "${WORK}/unsquashfs.log" \
         || echo "?")
echo "          → ${ROOT}  (≈${INODES} files extracted)"

echo
echo "[extract] top-level directories in the root filesystem:"
find "${ROOT}" -mindepth 1 -maxdepth 1 -printf "             %f\n" | sort

echo
echo "[extract] OpenWRT release stamp:"
if [[ -f "${ROOT}/etc/openwrt_release" ]]; then
  sed 's/^/             /' "${ROOT}/etc/openwrt_release"
else
  echo "             (no /etc/openwrt_release — not an OpenWRT image?)"
fi

echo
echo "[extract] done."
