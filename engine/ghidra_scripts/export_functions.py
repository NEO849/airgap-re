# -*- coding: utf-8 -*-
# export_functions.py -- Ghidra-headless Post-Script (Jython/Python2 im Ghidra-Kontext)
# Wird von re_triage.py via analyzeHeadless -postScript aufgerufen.
# Exportiert je Funktion: Name, Entry, aufgerufene Imports und (für risiko-nahe
# Funktionen) den dekompilierten C-Text → JSON an argv[0].
#
# Aufruf durch analyzeHeadless:
#   ... -postScript export_functions.py /pfad/out.json
#
# Läuft READ-ONLY (nur Analyse, kein Patch). Fehler in einer Funktion
# überspringt diese, bricht den Export nicht ab.
import json

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
except Exception:
    DecompInterface = None

RISKY = ("strcpy", "strcat", "sprintf", "gets", "memcpy", "memmove", "system",
         "popen", "exec", "scanf", "vsprintf", "strncpy", "read", "recv",
         "malloc", "alloca", "printf", "snprintf", "fscanf", "getenv")

def script_args():
    try:
        return list(getScriptArgs())  # noqa: F821 (Ghidra-Global)
    except Exception:
        return []

def called_import_names(func):
    names = set()
    try:
        for callee in func.getCalledFunctions(ConsoleTaskMonitor()):
            names.add(callee.getName())
    except Exception:
        pass
    return sorted(names)

def decompile_c(decomp, func):
    if decomp is None:
        return ""
    try:
        res = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
        if res and res.getDecompiledFunction():
            return res.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""

def main():
    args = script_args()
    out_path = args[0] if args else "/tmp/ghidra_export.json"

    program = currentProgram  # noqa: F821 (Ghidra-Global)
    fm = program.getFunctionManager()
    decomp = None
    if DecompInterface is not None:
        try:
            decomp = DecompInterface()
            decomp.openProgram(program)
        except Exception:
            decomp = None

    out = {"program": program.getName(), "functions": []}
    for func in fm.getFunctions(True):
        try:
            name = func.getName()
            entry = func.getEntryPoint().toString()
            calls = called_import_names(func)
            hits = [c for c in calls if any(r in c.lower() for r in RISKY)]
            c_text = ""
            # Dekompilat nur für risiko-nahe Funktionen (spart Zeit)
            if hits:
                c_text = decompile_c(decomp, func)
            out["functions"].append({
                "name": name,
                "entry": entry,
                "calls": calls,
                "risky_calls": hits,
                "decompiled": c_text[:8000],  # Deckel gegen Riesen-Funktionen
            })
        except Exception:
            continue

    f = open(out_path, "w")
    try:
        f.write(json.dumps(out))
    finally:
        f.close()
    print("[export_functions] %d Funktionen -> %s" % (len(out["functions"]), out_path))

main()
