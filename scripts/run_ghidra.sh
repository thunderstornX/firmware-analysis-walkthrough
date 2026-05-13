#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# run_ghidra.sh — wrapper around the PyGhidra headless launcher.
#
# Ghidra 12 deprecated bundled Jython in favour of PyGhidra (JPype
# bridge), so headless scripts are now plain CPython 3. We drive it
# through the `pyghidra` CLI installed into the project venv.
#
# Usage:  bash scripts/run_ghidra.sh <binary> [<heap_mib>]
# Default heap: 1500 MiB (tuned for low-RAM hosts).
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BINARY="${1:-}"
HEAP_MIB="${2:-1500}"

if [[ -z "${BINARY}" || ! -f "${BINARY}" ]]; then
  echo "Usage: bash scripts/run_ghidra.sh <binary> [<heap_mib>]" >&2
  exit 2
fi

: "${JAVA_HOME:=${HOME}/.local/share/jdk-21}"
: "${GHIDRA_HOME:=${HOME}/.local/share/ghidra}"
export JAVA_HOME PATH="${JAVA_HOME}/bin:${PATH}"
export GHIDRA_INSTALL_DIR="${GHIDRA_HOME}"

if [[ ! -x "${JAVA_HOME}/bin/java" ]]; then
  echo "ERROR: java not found at ${JAVA_HOME}/bin/java" >&2
  exit 3
fi
if [[ ! -d "${GHIDRA_HOME}/support" ]]; then
  echo "ERROR: Ghidra not found at ${GHIDRA_HOME}" >&2
  exit 4
fi

# Activate the project venv where pyghidra is installed.
VENV="${REPO_ROOT}/.venv"
if [[ ! -x "${VENV}/bin/pyghidra" ]]; then
  echo "ERROR: pyghidra not installed in ${VENV}." >&2
  echo "       activate the venv and:  pip install \\" >&2
  echo "         \"${GHIDRA_HOME}/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.0.2-py3-none-any.whl\"" >&2
  exit 5
fi
# shellcheck disable=SC1091
source "${VENV}/bin/activate"

PROJECT_DIR="${REPO_ROOT}/work/ghidra-project"
mkdir -p "${PROJECT_DIR}"
PROJECT_NAME="fw_audit"

# Wipe any previous import so re-runs are idempotent.
rm -rf "${PROJECT_DIR}/${PROJECT_NAME}.gpr" \
       "${PROJECT_DIR}/${PROJECT_NAME}.rep" 2>/dev/null || true

# Output goes here — read by ghidra_script.py via GHIDRA_AUDIT_OUT.
export GHIDRA_AUDIT_OUT="${REPO_ROOT}/results"
mkdir -p "${GHIDRA_AUDIT_OUT}"

# Heap cap forwarded to the JVM via _JAVA_OPTIONS (argparse on pyghidra's
# -X flag rejects values that begin with a dash, so this is the cleanest
# route).
export _JAVA_OPTIONS="-Xmx${HEAP_MIB}m -XX:+UseSerialGC"

echo "[ghidra] importing $(basename "${BINARY}") via pyghidra (heap=${HEAP_MIB}MiB)"
pyghidra \
    --project-path "${PROJECT_DIR}" \
    --project-name "${PROJECT_NAME}" \
    "${BINARY}" \
    "${REPO_ROOT}/scripts/ghidra_script.py" \
    > "${REPO_ROOT}/results/ghidra_stdout.txt" 2>&1

echo "[ghidra] done. report → results/ghidra_report.json"
echo "[ghidra]        stdout → results/ghidra_stdout.txt"
