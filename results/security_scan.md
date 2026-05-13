# DevSecOps gate results

Run on 2026-05-13 against the committed source tree.

| Gate | Version | Scope | Findings |
|---|---|---|---:|
| bandit | 1.9.x | `scripts/` | **0** (2 nosec annotations: `B404` subprocess import, `B603/B607` fixed-argv firmwalker invocation) |
| pip-audit | 2.7.x | `requirements.txt` | **0** |
| semgrep | 1.50+ | `scripts/`, `tests/` with `p/python` + `p/security-audit` | **0** |
| hadolint | 2.12.0 | `docker/Dockerfile` | **0** |
| shellcheck | system | `scripts/*.sh`, `docker/*.sh` | **0** |

## Re-running the gates

```
source .venv/bin/activate
bandit  -r scripts/
pip-audit -r requirements.txt
semgrep --config p/python --config p/security-audit scripts/ tests/
hadolint docker/Dockerfile
shellcheck scripts/extract.sh scripts/run_ghidra.sh docker/install_ghidra.sh
```

## bandit nosec rationale

| ID | Location | Why suppressed |
|---|---|---|
| B404 | `scripts/enumerate.py:19` (subprocess import) | The module is used **only** to drive `firmwalker.sh` with a fixed argv. No shell, no user input. |
| B603/B607 | `scripts/enumerate.py:107` (argv list) | `bash` is resolved via PATH, but the argv is a constant list assembled from a validated path. No injection surface. |
```
