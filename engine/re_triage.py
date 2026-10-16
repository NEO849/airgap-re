#!/usr/bin/env python3
"""
re_triage.py — Agentische Binär-Triage (Ghidra + capa + floss + Sink-Rank + angr)

Kombiniert vorhandenes (capa/floss/r2) mit neuem (Ghidra-headless/angr) zu einer
Fähigkeit, die kein Einzeltool liefert: EIN Lauf → gerankter "verdächtige
Funktionen"-Report + optional symbolischer PoC-Input-Kandidat.

Pipeline:
  1. Funktions-Inventar   : Ghidra-headless (export_functions.py) ODER r2/rizin-Fallback
  2. Capability-Enrichment: capa -j   (welche Fähigkeiten hat das Binary?)
  3. String-Enrichment    : floss -j  (--strings, entschlüsselte Strings; opt-in/timeout)
  4. Sink-Heuristik       : rankt Funktionen nach gefährlichen Sinks (memcpy/system/format-string/…)
  5. Symbolik (opt-in)    : angr fährt gezielt Top-N-Sink-Adressen an → erreichbar? Constraints?
  6. Report               : Markdown + JSON

HARD-GATES: READ-ONLY am Artefakt (kein Patch, keine Ausführung des Ziels).
Ziel-Binaries nur autorisiert / lab / eigene APKs. HANDOFF an reverse-engineer /
skeptical-validator (45%-Cap: "erreichbar" ist Hypothese, kein bestätigter Bug).

Beispiele:
  re_triage.py ./target                      # schnell: Inventar + capa + Sink-Rank
  re_triage.py ./target --symbolic --top 5   # + angr auf Top-5-Sinks
  re_triage.py ./target --floss --json out.json
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

RE_VENV_PY = os.environ.get("REMCP_VENV_PY", "/opt/re-venv/bin/python")   # angr-venv; env-überschreibbar
GHIDRA_SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")

# Gefährliche Sinks → Gewicht (grob nach Impact/Exploitierbarkeit)
SINK_WEIGHTS = {
    "system": 10, "popen": 10, "execve": 10, "execl": 9, "execlp": 9, "execvp": 9,
    "gets": 9, "strcpy": 7, "strcat": 7, "sprintf": 7, "vsprintf": 7, "scanf": 6,
    "memcpy": 5, "memmove": 5, "alloca": 5, "printf": 4, "fprintf": 3, "snprintf": 3,
    "getenv": 3, "read": 2, "recv": 2, "malloc": 2, "fscanf": 4, "strncpy": 3,
    # Deserialisierung / gefährliche Muster (Text-Match im Dekompilat)
    "deserialize": 8, "unserialize": 8, "pickle": 8, "eval": 9, "dlopen": 6,
    # Android/JNI-Brücken
    "RegisterNatives": 6, "CallObjectMethod": 4, "GetStringUTFChars": 4,
}


def sh(cmd, timeout=None, capture=True):
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


def have(binname):
    return shutil.which(binname) is not None


# ---------- Stufe 1: Funktions-Inventar ----------
def inventory_ghidra(binary):
    """Ghidra-headless → export_functions.py → JSON. None wenn Ghidra fehlt/scheitert."""
    if not have("ghidra-headless"):
        return None
    proj = tempfile.mkdtemp(prefix="ghidra_re_")
    out_json = os.path.join(proj, "export.json")
    cmd = ["ghidra-headless", proj, "triage",
           "-import", binary,
           "-scriptPath", GHIDRA_SCRIPT_DIR,
           "-postScript", "export_functions.py", out_json,
           "-deleteProject"]
    print("[*] Ghidra-headless Analyse (kann dauern)…", file=sys.stderr)
    rc, out, err = sh(cmd, timeout=1800)
    data = None
    if os.path.exists(out_json):
        try:
            with open(out_json) as f:
                data = json.load(f)
        except Exception:
            data = None
    shutil.rmtree(proj, ignore_errors=True)
    if data:
        print("[+] Ghidra: %d Funktionen" % len(data.get("functions", [])), file=sys.stderr)
    return data


def inventory_r2(binary):
    """Fallback: r2/rizin liefert Funktionsliste + attribuiert Sink-Imports pro Funktion
    (via axt = Xrefs zu jedem Sink-Import → aufrufende Funktion). Kein Dekompilat-Tiefe."""
    tool = "r2" if have("r2") else ("rizin" if have("rizin") else None)
    if not tool:
        return None
    print("[*] %s-Fallback-Inventar…" % tool, file=sys.stderr)
    # Pass 1: Funktionsliste + Imports in EINEM Lauf (aa+aar für Xref-Analyse)
    rc, out, err = sh([tool, "-q", "-e", "bin.relocs.apply=true",
                       "-c", "aa;aar;?e ===FUNCS===;aflj;?e ===IMPORTS===;iij", binary], timeout=600)
    funcs_by_name = {}
    order = []
    imports = []
    try:
        seg = out.split("===FUNCS===", 1)[1]
        funcs_part, imports_part = seg.split("===IMPORTS===", 1)
        for fn in json.loads(funcs_part.strip() or "[]"):
            name = fn.get("name", "")
            rec = {"name": name, "entry": hex(fn.get("offset", 0)),
                   "calls": [], "risky_calls": [], "decompiled": ""}
            funcs_by_name[name] = rec
            order.append(rec)
        imports = [i.get("name", "") for i in json.loads(imports_part.strip() or "[]") if i.get("name")]
    except Exception:
        pass

    # Pass 2: für jeden Sink-Import die Xrefs holen → aufrufende Funktion markieren
    sink_imports = [i for i in imports if any(s in i.lower() for s in SINK_WEIGHTS)]
    if sink_imports and funcs_by_name:
        cmds = []
        for imp in sink_imports:
            flag = "sym.imp.%s" % imp
            # Marker OHNE '@' — '@@@' ist in r2 ein Iterator-Operator und würde interpretiert
            cmds.append("?e __SINK__%s__SINK__" % imp)
            cmds.append("axtj %s" % flag)
        rc2, out2, _ = sh([tool, "-q", "-c", "aa;aar;" + ";".join(cmds), binary], timeout=600)
        # out2 blockweise parsen: __SINK__name__SINK__ \n <axtj-json>
        blocks = re.split(r"__SINK__([A-Za-z0-9_]+)__SINK__", out2)
        # blocks: ["", name1, json1, name2, json2, ...]
        for i in range(1, len(blocks) - 1, 2):
            imp = blocks[i]
            payload = blocks[i + 1].strip()
            try:
                xrefs = json.loads(payload or "[]")
            except Exception:
                xrefs = []
            for xr in xrefs:
                fname = xr.get("fcn_name") or xr.get("realname") or ""
                if fname in funcs_by_name and imp not in funcs_by_name[fname]["risky_calls"]:
                    funcs_by_name[fname]["risky_calls"].append(imp)

    if order:
        print("[+] %s: %d Funktionen, %d Imports (%d Sink-Imports attribuiert)"
              % (tool, len(order), len(imports), len(sink_imports)), file=sys.stderr)
    return {"program": os.path.basename(binary), "functions": order, "imports": imports}


def build_inventory(binary, prefer_r2=False):
    data = None
    if not prefer_r2:
        data = inventory_ghidra(binary)
    if data is None:
        data = inventory_r2(binary)
    if data is None:
        print("[!] Kein Inventar-Backend (weder ghidra-headless noch r2/rizin). "
              "Installiere via install_re_automation.sh.", file=sys.stderr)
        data = {"program": os.path.basename(binary), "functions": [], "imports": []}
    return data


# ---------- Stufe 2/3: capa + floss Enrichment ----------
def enrich_capa(binary):
    if not have("capa"):
        return {"available": False}
    print("[*] capa (Capabilities)…", file=sys.stderr)
    capa_cmd = ["capa", "-j", binary]
    # capa (pip/flare-capa) bringt KEIN Rule-Set mit → ohne -r schlägt es fehl.
    # Passendes Rule-Set liegt in /opt/capa-rules (Tag an capa-Version gepinnt).
    _capa_rules = os.environ.get("CAPA_RULES", "/opt/capa-rules")
    if os.path.isdir(_capa_rules):
        capa_cmd = ["capa", "-j", "-r", _capa_rules, binary]
    rc, out, err = sh(capa_cmd, timeout=600)
    if rc != 0 or not out:
        return {"available": True, "error": err[:200]}
    try:
        j = json.loads(out)
        rules = list((j.get("rules") or {}).keys())
        return {"available": True, "capabilities": rules[:60], "count": len(rules)}
    except Exception:
        return {"available": True, "error": "parse"}


def enrich_floss(binary, timeout):
    if not have("floss"):
        return {"available": False}
    print("[*] floss (entschlüsselte Strings, timeout=%ds)…" % timeout, file=sys.stderr)
    rc, out, err = sh(["floss", "-j", binary], timeout=timeout)
    if rc == 124:
        return {"available": True, "error": "timeout"}
    if rc != 0 or not out:
        return {"available": True, "error": err[:200]}
    try:
        j = json.loads(out)
        strings = j.get("strings", {})
        # interessante Marker: URLs, Pfade, Format-Strings, Cmd-Fragmente
        flat = []
        for k in ("decoded_strings", "stack_strings", "static_strings"):
            for s in (strings.get(k) or []):
                val = s.get("string") if isinstance(s, dict) else str(s)
                if val:
                    flat.append(val)
        interesting = [s for s in flat if re.search(r"(https?://|/bin/|%s|%n|\.\./|cmd|passwd|token|secret|key=)", s, re.I)]
        return {"available": True, "total": len(flat), "interesting": interesting[:40]}
    except Exception:
        return {"available": True, "error": "parse"}


# ---------- Stufe 4: Sink-Heuristik ----------
def score_functions(inventory):
    ranked = []
    for fn in inventory.get("functions", []):
        text = (fn.get("decompiled") or "").lower()
        calls = [c.lower() for c in fn.get("calls", [])] + [c.lower() for c in fn.get("risky_calls", [])]
        score = 0
        hits = {}
        for sink, w in SINK_WEIGHTS.items():
            sl = sink.lower()
            n = sum(1 for c in calls if sl in c)
            n += len(re.findall(r"\b" + re.escape(sl) + r"\b", text))
            if n:
                score += w * n
                hits[sink] = n
        # Format-String-Verdacht: printf-Familie mit nicht-konstantem 1. Arg (heuristisch)
        if re.search(r"(printf|sprintf|fprintf)\s*\(\s*[a-z_][a-z0-9_]*\s*[,)]", text):
            score += 4
            hits["fmt-string-suspect"] = hits.get("fmt-string-suspect", 0) + 1
        if score > 0:
            ranked.append({"name": fn["name"], "entry": fn["entry"], "score": score, "sinks": hits})
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked


# ---------- Stufe 5: angr Symbolik (opt-in) ----------
ANGR_DRIVER = r'''
import sys, json
try:
    import angr, claripy  # noqa
except Exception as e:
    print(json.dumps({"error": "angr import: %s" % e})); sys.exit(0)

binary = sys.argv[1]
targets = json.loads(sys.argv[2])   # Liste hex-Adressen
timeout = int(sys.argv[3])

import signal
class TO(Exception): pass
def _t(sig, frm): raise TO()
signal.signal(signal.SIGALRM, _t)

out = []
try:
    proj = angr.Project(binary, auto_load_libs=False)
except Exception as e:
    print(json.dumps({"error": "load: %s" % e})); sys.exit(0)

for taddr in targets:
    try:
        addr = int(taddr, 16)
    except Exception:
        continue
    signal.alarm(timeout)
    res = {"target": taddr, "reachable": False}
    try:
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=addr, num_find=1)
        if simgr.found:
            res["reachable"] = True
            f = simgr.found[0]
            try:
                stdin_bytes = f.posix.dumps(0)
                res["stdin_input"] = stdin_bytes[:200].hex()
            except Exception:
                pass
    except TO:
        res["note"] = "timeout (state explosion) — Pfad nicht widerlegt, nur nicht bewiesen"
    except Exception as e:
        res["note"] = "angr: %s" % str(e)[:120]
    finally:
        signal.alarm(0)
    out.append(res)

print(json.dumps({"results": out}))
'''


def run_angr(binary, ranked, top, per_target_timeout):
    py = RE_VENV_PY if os.path.exists(RE_VENV_PY) else None
    if py is None:
        # Fallback: system python falls angr global installiert
        try:
            import angr  # noqa
            py = sys.executable
        except Exception:
            return {"available": False, "note": "angr venv fehlt (install_re_automation.sh)"}
    targets = [f["entry"] for f in ranked[:top]]
    if not targets:
        return {"available": True, "results": []}
    print("[*] angr symbolisch auf Top-%d Sink-Funktionen (timeout %ds/Ziel)…" % (len(targets), per_target_timeout),
          file=sys.stderr)
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(ANGR_DRIVER)
        driver = tf.name
    rc, out, err = sh([py, driver, binary, json.dumps(targets), str(per_target_timeout)],
                      timeout=per_target_timeout * len(targets) + 60)
    os.unlink(driver)
    try:
        return dict({"available": True}, **json.loads(out or "{}"))
    except Exception:
        return {"available": True, "error": err[:300] or "parse", "raw": out[:300]}


# ---------- Stufe 6: Report ----------
def render_report(binary, inv, capa, floss, ranked, angr_res):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L = []
    L.append("# RE-Triage: `%s`" % os.path.basename(binary))
    L.append("")
    L.append("- Zeit: %s" % ts)
    L.append("- Funktionen inventarisiert: %d" % len(inv.get("functions", [])))
    if capa.get("available"):
        L.append("- capa: %s Capabilities" % capa.get("count", "?"))
    if floss.get("available") and "total" in floss:
        L.append("- floss: %d Strings, %d interessant" % (floss.get("total", 0), len(floss.get("interesting", []))))
    L.append("")
    L.append("> ⚠️ 45%%-Cap: 'Sink erreichbar' ist eine **Hypothese**, kein bestätigter Bug. "
             "HANDOFF → reverse-engineer / skeptical-validator für echten PoC.")
    L.append("")

    L.append("## Top verdächtige Funktionen (Sink-Rank)")
    if not ranked:
        L.append("_Keine Sink-Treffer — Ghidra-Dekompilat evtl. nötig (r2-Fallback sieht weniger)._")
    for i, f in enumerate(ranked[:20], 1):
        sinks = ", ".join("%s×%d" % (k, v) for k, v in sorted(f["sinks"].items(), key=lambda x: -x[1]))
        L.append("%d. **%s** @ %s — Score %d — Sinks: %s" % (i, f["name"], f["entry"], f["score"], sinks))
    L.append("")

    if capa.get("available") and capa.get("capabilities"):
        L.append("## capa-Capabilities (Auszug)")
        for c in capa["capabilities"][:25]:
            L.append("- %s" % c)
        L.append("")

    if floss.get("interesting"):
        L.append("## floss — interessante Strings")
        for s in floss["interesting"]:
            L.append("- `%s`" % s.replace("`", "'")[:160])
        L.append("")

    if angr_res and angr_res.get("available"):
        L.append("## angr — symbolische Erreichbarkeit (Top-Sinks)")
        if angr_res.get("error"):
            L.append("_Fehler: %s_" % angr_res["error"])
        for r in angr_res.get("results", []):
            flag = "✅ ERREICHBAR" if r.get("reachable") else "—"
            extra = ""
            if r.get("stdin_input"):
                extra = " · stdin(hex, gekürzt): `%s`" % r["stdin_input"]
            if r.get("note"):
                extra += " · %s" % r["note"]
            L.append("- %s @ %s%s" % (flag, r["target"], extra))
        L.append("")

    L.append("## Nächster Schritt")
    L.append("- Top-Funktion manuell im Ghidra-Dekompilat prüfen (Datenfluss zur Sink-Quelle).")
    L.append("- Bei angr-ERREICHBAR: stdin_input als Ausgangs-PoC nehmen, mit skeptical-validator härten.")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="RE-Triage: Ghidra+capa+floss+Sink-Rank+angr")
    ap.add_argument("binary", help="Zielbinary (ELF/PE/Mach-O/native .so). READ-ONLY.")
    ap.add_argument("--symbolic", action="store_true", help="angr auf Top-N-Sinks fahren (schwer)")
    ap.add_argument("--floss", action="store_true", help="floss-Strings-Enrichment (langsam)")
    ap.add_argument("--top", type=int, default=5, help="Anzahl Sink-Funktionen für angr (default 5)")
    ap.add_argument("--angr-timeout", type=int, default=120, help="Sekunden/Ziel für angr (default 120)")
    ap.add_argument("--floss-timeout", type=int, default=300, help="Sekunden für floss (default 300)")
    ap.add_argument("--prefer-r2", action="store_true", help="r2-Inventar erzwingen (Ghidra überspringen)")
    ap.add_argument("--json", help="JSON-Report zusätzlich hierhin schreiben")
    ap.add_argument("--md", help="Markdown-Report hierhin schreiben (sonst stdout)")
    args = ap.parse_args()

    if not os.path.exists(args.binary):
        print("[!] Datei nicht gefunden: %s" % args.binary, file=sys.stderr)
        sys.exit(2)

    inv = build_inventory(args.binary, prefer_r2=args.prefer_r2)
    capa = enrich_capa(args.binary)
    floss = enrich_floss(args.binary, args.floss_timeout) if args.floss else {"available": False}
    ranked = score_functions(inv)
    angr_res = run_angr(args.binary, ranked, args.top, args.angr_timeout) if args.symbolic else None

    report = render_report(args.binary, inv, capa, floss, ranked, angr_res)
    if args.md:
        with open(args.md, "w") as f:
            f.write(report)
        print("[+] Markdown-Report → %s" % args.md, file=sys.stderr)
    else:
        print(report)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"binary": args.binary, "inventory_count": len(inv.get("functions", [])),
                       "capa": capa, "floss": floss, "ranked": ranked, "angr": angr_res}, f, indent=2)
        print("[+] JSON-Report → %s" % args.json, file=sys.stderr)


if __name__ == "__main__":
    main()
