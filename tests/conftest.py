"""Test setup — put the repo root on sys.path so we can import the
analysis scripts as flat modules without packaging gymnastics."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS   = REPO_ROOT / "scripts"

for p in (str(REPO_ROOT), str(SCRIPTS)):
    if p not in sys.path:
        sys.path.insert(0, p)
