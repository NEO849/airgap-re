# -*- coding: utf-8 -*-
# decompile_function.py -- Ghidra-headless Post-Script (Jython/Python2 im Ghidra-Kontext)
# Dekompiliert GENAU EINE Funktion (nach Name oder Entry-Adresse) -> JSON an argv[0].
# Aufruf: ... -postScript decompile_function.py <out.json> <name_or_0xADDR>
#
# READ-ONLY (nur Analyse). Teil der Eigenbau-RE-MCP-Brücke (re-mcp), NICHT von REA.
import json

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
except Exception:
    DecompInterface = None


def script_args():
    try:
        return list(getScriptArgs())  # noqa: F821 (Ghidra-Global)
    except Exception:
        return []


def find_function(program, target):
    fm = program.getFunctionManager()
    # 1) Adresse? (0x... oder hex)
    addr_str = target
    if addr_str.lower().startswith("0x"):
        addr_str = addr_str[2:]
    try:
        addr = program.getAddressFactory().getAddress(addr_str)
        if addr is not None:
            f = fm.getFunctionAt(addr)
            if f is not None:
                return f
            f = fm.getFunctionContaining(addr)
            if f is not None:
                return f
    except Exception:
        pass
    # 2) exakter Name
    for f in fm.getFunctions(True):
        if f.getName() == target:
            return f
    # 3) case-insensitiver Teiltreffer (erster)
    tl = target.lower()
    for f in fm.getFunctions(True):
        if tl in f.getName().lower():
            return f
    return None


def main():
    args = script_args()
    out_path = args[0] if args else "/tmp/ghidra_decompile.json"
    target = args[1] if len(args) > 1 else ""

    program = currentProgram  # noqa: F821 (Ghidra-Global)
    out = {"program": program.getName(), "target": target, "found": False,
           "name": None, "entry": None, "signature": None, "decompiled": "", "error": None}

    try:
        func = find_function(program, target)
        if func is None:
            out["error"] = "Funktion nicht gefunden: %s" % target
        else:
            out["found"] = True
            out["name"] = func.getName()
            out["entry"] = func.getEntryPoint().toString()
            try:
                out["signature"] = func.getSignature().getPrototypeString()
            except Exception:
                out["signature"] = None
            if DecompInterface is not None:
                decomp = DecompInterface()
                decomp.openProgram(program)
                res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
                if res and res.getDecompiledFunction():
                    out["decompiled"] = res.getDecompiledFunction().getC()[:40000]
                else:
                    out["error"] = "Dekompilierung lieferte kein Ergebnis"
            else:
                out["error"] = "DecompInterface nicht verfügbar"
    except Exception as e:
        out["error"] = "Ausnahme: %s" % str(e)[:300]

    f = open(out_path, "w")
    try:
        f.write(json.dumps(out))
    finally:
        f.close()
    print("[decompile_function] target=%s found=%s -> %s" % (target, out["found"], out_path))


main()
