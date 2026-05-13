"""Ghidra headless analysis script — runs under PyGhidra (CPython 3).

Driven by ``scripts/run_ghidra.sh``, which calls the ``pyghidra`` CLI:

  pyghidra <binary> scripts/ghidra_script.py

The Ghidra runtime injects ``currentProgram`` (and friends) into the
module globals, so the API surface is identical to the legacy Jython
scripts.

The script lists every imported function, every exported symbol, a
selection of suspicious calls (system, exec, strcpy family, sprintf,
gets, …), and printable strings of meaningful length. Output is
written to ``$GHIDRA_AUDIT_OUT/ghidra_report.json``.

Targets the busybox binary extracted from OpenWRT 22.03.7
(ath79/mips_24kc), but is binary-agnostic.
"""
# @category Audit
# @author firmware-analysis-walkthrough

import json
import os
import tempfile

SUSPICIOUS_FUNCS = (
    "system", "popen", "execve", "execvp", "execl", "execlp",
    "strcpy", "strcat", "sprintf", "gets",
    "memcpy",
    "setuid", "setgid", "seteuid",
)

# Strings we surface from the program: minimum length filter
MIN_STRING_LEN = 12


def collect_imports():
    """Imported (external) functions referenced from the binary."""
    out = []
    fm = currentProgram.getFunctionManager()
    for f in fm.getExternalFunctions():
        out.append({
            "name":        f.getName(),
            "address":     str(f.getEntryPoint()) if f.getEntryPoint() else None,
            "library":     str(f.getExternalLocation().getLibraryName())
                            if f.getExternalLocation() else None,
        })
    return out


def collect_exports():
    """Exported symbols (entry points the binary publishes)."""
    out = []
    sm = currentProgram.getSymbolTable()
    it = sm.getExternalEntryPointIterator()
    while it.hasNext():
        addr = it.next()
        sym  = sm.getPrimarySymbol(addr)
        if sym is None:
            continue
        out.append({
            "name":    sym.getName(),
            "address": str(addr),
        })
    return out


def _iter_java(it):
    """Iterate a Java Iterator/SymbolIterator/ReferenceIterator.

    JPype/PyGhidra does not always wire up Python iteration on Java
    iterators, so we go through hasNext/next explicitly.
    """
    try:
        while it.hasNext():
            yield it.next()
    except AttributeError:
        # Already a Python-iterable (e.g. a list).
        yield from it


def collect_suspicious_xrefs():
    """For each suspicious libc function name, surface the in-binary
    call-sites.

    External symbols live at a pseudo-address (``EXTERNAL:00000055``)
    with no direct references; the real call-sites reach them through
    *thunks* at concrete addresses in the binary. We index thunks by
    their thunked-function name once, then look up references against
    each thunk's entry point.
    """
    fm = currentProgram.getFunctionManager()
    rm = currentProgram.getReferenceManager()

    # name → [thunk_function, …]
    thunks_by_target: dict[str, list] = {n: [] for n in SUSPICIOUS_FUNCS}
    for fn in _iter_java(fm.getFunctions(True)):
        if not fn.isThunk():
            continue
        tgt = fn.getThunkedFunction(True)
        if tgt is None:
            continue
        tname = tgt.getName()
        if tname in thunks_by_target:
            thunks_by_target[tname].append(fn)

    out = []
    for name in SUSPICIOUS_FUNCS:
        callers_seen: set[str] = set()
        xrefs: list[dict] = []
        for thunk in thunks_by_target.get(name, []):
            entry = thunk.getEntryPoint()
            for r in _iter_java(rm.getReferencesTo(entry)):
                caller_addr = r.getFromAddress()
                key = str(caller_addr)
                if key in callers_seen:
                    continue
                callers_seen.add(key)
                caller = fm.getFunctionContaining(caller_addr)
                xrefs.append({
                    "from":     key,
                    "thunk":    str(entry),
                    "caller":   caller.getName() if caller else None,
                })
        if xrefs:
            out.append({
                "name":          name,
                "thunk_count":   len(thunks_by_target.get(name, [])),
                "xrefs":         xrefs[:50],  # cap to keep the report small
                "xrefs_total":   len(xrefs),
            })
    return out


def collect_strings(min_len=MIN_STRING_LEN, cap=500):
    """Defined-string artefacts of meaningful length."""
    out = []
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    while it.hasNext() and len(out) < cap:
        d = it.next()
        if d.getDataType().getName().lower() in ("string", "unicode", "tstring"):
            v = d.getValue()
            s = str(v) if v else ""
            if len(s) >= min_len:
                out.append({"address": str(d.getAddress()),
                            "string":  s[:200]})
    return out


def main():
    program_name = currentProgram.getName()
    arch         = currentProgram.getLanguage().getProcessor().toString()
    endian       = "big" if currentProgram.getLanguage().isBigEndian() else "little"
    bitness      = currentProgram.getLanguage().getLanguageDescription().getSize()

    report = {
        "program":  program_name,
        "arch":     arch,
        "endian":   endian,
        "bits":     bitness,
        "imports":  collect_imports(),
        "exports":  collect_exports(),
        "suspicious_xrefs": collect_suspicious_xrefs(),
        "strings":  collect_strings(),
    }

    out_dir = os.environ.get("GHIDRA_AUDIT_OUT") or tempfile.mkdtemp(
        prefix="ghidra_audit_")
    out_path = os.path.join(out_dir, "ghidra_report.json")
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    print("[ghidra_script] wrote " + out_path)
    print("[ghidra_script] imports=%d  exports=%d  suspicious=%d  strings=%d" %
          (len(report["imports"]), len(report["exports"]),
           len(report["suspicious_xrefs"]), len(report["strings"])))


main()
