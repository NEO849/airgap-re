#!/usr/bin/env python3
"""
sandboxed-re-mcp — security-first Reverse-Engineering MCP server.

Konzept wie generische "KI steuert RE-Werkzeuge über MCP"-Server, aber mit einem
nicht verhandelbaren Unterschied: der Pfad für UNTRUSTED Samples läuft in einer
bubblewrap-Wegwerfkammer OHNE Netz und mit Ressourcen-Obergrenzen. Das Ziel wird
NIE ausgeführt — jede Analyse ist statisch.

Backends (alle extern, auto-discovered): Ghidra-headless · re_triage.py
(capa/floss/Sink-Rang/angr) · r2/rizin · jadx/apktool (nativ-Schicht via APK-Triage).

HARD-GATES:
  - READ-ONLY am Ziel: alle Backends analysieren statisch, führen das Ziel NIE aus.
  - stdio-MCP: NUR das Protokoll darf auf stdout. Logs gehen nach stderr/Datei.
  - Untrusted Samples -> sandbox_analyze_binary (bwrap --unshare-all, keine Caps,
    cgroup Mem/PID/CPU-Limits).
  - Autorisierte Nutzung: eigener Code / in-scope Bug-Bounty / CTF / eigene Geräte.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile

from mcp.server.fastmcp import FastMCP

from . import config

# ---------- Logging: NIE auf stdout (das ist der MCP-Kanal) ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(config.LOG_PATH), logging.StreamHandler(sys.stderr)],
)
log = logging.getLogger("re-mcp")

mcp = FastMCP("re-mcp")


# ---------- Helfer ----------
def _validate(path: str, want_suffix: str | None = None) -> str | None:
    """Pfad prüfen: existiert, Datei, Grössen-Deckel. Gibt Fehlertext oder None."""
    if not path or not isinstance(path, str):
        return "Kein Pfad angegeben."
    if not os.path.isabs(path):
        return "Bitte ABSOLUTEN Pfad angeben (Pfad war relativ): %s" % path
    if not os.path.exists(path):
        return "Datei nicht gefunden: %s" % path
    if not os.path.isfile(path):
        return "Kein regulärer Datei-Pfad: %s" % path
    try:
        if os.path.getsize(path) > config.MAX_BYTES:
            return "Datei > Limit — abgelehnt (Schutz): %s" % path
    except OSError as e:
        return "Pfad nicht lesbar: %s (%s)" % (path, e)
    if want_suffix and not path.lower().endswith(want_suffix):
        return "Erwarte %s-Datei, bekam: %s" % (want_suffix, path)
    return None


def _run(cmd, timeout):
    """Subprocess, Ausgabe gekapselt (erreicht NIE unser stdout)."""
    log.info("run: %s", " ".join(str(c) for c in cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout nach %ss" % timeout
    except FileNotFoundError as e:
        return 127, "", "Kommando nicht gefunden: %s" % e


def _r2(binary, pipeline):
    tool = "r2" if shutil.which("r2") else ("rizin" if shutil.which("rizin") else None)
    if not tool:
        return None, "weder r2 noch rizin vorhanden"
    rc, out, err = _run([tool, "-q", "-c", pipeline, binary], 300)
    if rc != 0 and not out:
        return None, (err[:300] or "r2 exit %s" % rc)
    return out, None


# ---------- Tools ----------
@mcp.tool()
def re_capabilities() -> str:
    """Health-Check: welche RE-Backends sind verfügbar (Ghidra/r2/capa/floss/angr/jadx/apktool/bwrap)
    + Versionen. Immer zuerst aufrufen, wenn unklar ist, was geht."""
    caps: dict[str, object] = {}
    caps["ghidra_headless"] = config.ghidra_available()
    for t in ("r2", "rizin", "capa", "floss", "jadx", "apktool", "bwrap", "systemd-run"):
        caps[t] = config.tool_available(t)
    caps["angr_venv"] = os.path.exists(config.VENV_PY)
    caps["re_triage"] = os.path.exists(config.RE_TRIAGE)
    caps["apk_triage"] = os.path.exists(config.APK_TRIAGE)
    caps["sandbox_wrapper"] = os.path.exists(config.SANDBOX)
    try:
        v = subprocess.run([config.GHIDRA_HEADLESS], capture_output=True, text=True, timeout=20)
        caps["ghidra_note"] = "aufrufbar" if (v.stdout or v.stderr) else "?"
    except Exception:
        caps["ghidra_note"] = "?"
    return json.dumps(caps, indent=2, ensure_ascii=False)


@mcp.tool()
def analyze_binary(path: str, floss: bool = False, symbolic: bool = False) -> str:
    """Volle statische Triage eines nativen Binaries (ELF/PE/Mach-O/.so) HOST-seitig via re_triage.py:
    Ghidra-Dekompilat -> capa-Capabilities -> floss-Strings (opt) -> Sink-Rang -> angr (opt).
    Liefert strukturiertes JSON (Top-verdächtige Funktionen, Capabilities, Strings).
    READ-ONLY. Für EIGENE / in-scope / CTF-Binaries. Fremde/untrusted Samples -> sandbox_analyze_binary.
    Kann mehrere Minuten dauern (Ghidra-Analyse)."""
    err = _validate(path)
    if err:
        return json.dumps({"error": err})
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        jp = tf.name
    cmd = [sys.executable, str(config.RE_TRIAGE), path, "--json", jp, "--md", os.devnull]
    if floss:
        cmd.append("--floss")
    if symbolic:
        cmd.append("--symbolic")
    rc, out, serr = _run(cmd, config.TIMEOUT_TRIAGE)
    data = None
    try:
        with open(jp) as f:
            data = json.load(f)
    except Exception:
        data = None
    finally:
        try:
            os.unlink(jp)
        except OSError:
            pass
    if data is None:
        return json.dumps({"error": "Triage lieferte kein JSON", "rc": rc, "stderr": serr[:500]})
    slim = {
        "binary": data.get("binary"),
        "functions_inventoried": data.get("inventory_count"),
        "capa": data.get("capa"),
        "floss": data.get("floss"),
        "top_suspicious_functions": (data.get("ranked") or [])[:25],
        "angr": data.get("angr"),
        "note": "45%-Cap: 'Sink erreichbar' ist Hypothese, kein bestätigter Bug.",
    }
    return json.dumps(slim, ensure_ascii=False)


@mcp.tool()
def sandbox_analyze_binary(path: str, floss: bool = False) -> str:
    """Wie analyze_binary, aber ISOLIERT in einer bubblewrap-Wegwerfkammer:
    --unshare-all (KEIN Netz -> Egress strukturell unmöglich), keine Capabilities,
    cgroup Mem/PID/CPU-Limits, Host read-only, kein Host-Secret. Für UNTRUSTED / fremde Samples.
    Braucht bwrap (bubblewrap). READ-ONLY, Ziel wird NIE ausgeführt."""
    err = _validate(path)
    if err:
        return json.dumps({"error": err})
    if not config.tool_available("bwrap"):
        return json.dumps({"error": "bwrap (bubblewrap) nicht verfügbar — installiere bubblewrap, "
                                    "oder nutze analyze_binary nur für eigene/in-scope Dateien."})
    cmd = ["bash", str(config.SANDBOX), path] + (["--floss"] if floss else [])
    rc, out, serr = _run(cmd, config.TIMEOUT_SANDBOX)
    if rc != 0:
        return json.dumps({"error": "Sandbox-Analyse fehlgeschlagen", "rc": rc, "stderr": serr[:800]})
    try:
        return json.dumps(json.loads(out), ensure_ascii=False)
    except Exception:
        return json.dumps({"raw": out[:4000], "stderr": serr[:400]})


@mcp.tool()
def sandbox_selftest() -> str:
    """Beweist LIVE die Isolations-Garantien der Sandbox (keine Analyse eines Ziels):
    (1) Netz-Zugriff in der Kammer schlägt fehl, (2) Schreiben auf den Host-Pfad scheitert.
    Gibt pro Check PASS/FAIL zurück — die messbaren Security-Claims, selbst nachprüfbar."""
    if not config.tool_available("bwrap"):
        return json.dumps({"error": "bwrap nicht verfügbar"})
    results = {}
    # Check 1: kein Egress — Verbindungsversuch MUSS fehlschlagen
    net = ("import socket,sys\n"
           "try:\n"
           "  socket.setdefaulttimeout(3); socket.create_connection(('1.1.1.1',53))\n"
           "  print('REACHED'); sys.exit(0)\n"
           "except Exception:\n"
           "  print('BLOCKED'); sys.exit(0)\n")
    rc, out, _ = _run(["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr",
                       "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
                       *(["--ro-bind", "/lib64", "/lib64"] if os.path.exists("/lib64") else []),
                       "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                       "/usr/bin/python3", "-c", net], 60)
    results["no_network_egress"] = "PASS" if "BLOCKED" in out else "FAIL(%s)" % (out.strip() or rc)
    # Check 2: Host-Schreibschutz — Schreiben nach /etc (ro-bind) MUSS scheitern
    wr = ("import sys\n"
          "try:\n"
          "  open('/usr/_remcp_probe','w').write('x'); print('WROTE'); sys.exit(0)\n"
          "except Exception:\n"
          "  print('READONLY'); sys.exit(0)\n")
    rc, out, _ = _run(["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr",
                       "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
                       *(["--ro-bind", "/lib64", "/lib64"] if os.path.exists("/lib64") else []),
                       "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                       "/usr/bin/python3", "-c", wr], 60)
    results["host_filesystem_readonly"] = "PASS" if "READONLY" in out else "FAIL(%s)" % (out.strip() or rc)
    results["verdict"] = "PASS" if all(v == "PASS" for v in results.values()) else "FAIL"
    return json.dumps(results, indent=2, ensure_ascii=False)


@mcp.tool()
def decompile_function(path: str, function: str) -> str:
    """Dekompiliert GENAU EINE Funktion (nach Name oder Entry-Adresse 0x...) via Ghidra-headless -> C-Text + Signatur.
    'function' z.B. 'main', 'check_license' oder '0x401160'. READ-ONLY. Kann einige Minuten dauern."""
    err = _validate(path)
    if err:
        return json.dumps({"error": err})
    if not function:
        return json.dumps({"error": "Parameter 'function' (Name oder 0xAddr) fehlt."})
    if not config.ghidra_available():
        return json.dumps({"error": "Ghidra-headless nicht gefunden: %s" % config.GHIDRA_HEADLESS})
    proj = tempfile.mkdtemp(prefix="remcp_ghidra_")
    out_json = os.path.join(proj, "decomp.json")
    cmd = [config.GHIDRA_HEADLESS, proj, "remcp", "-import", path,
           "-scriptPath", str(config.GHIDRA_SCRIPTS),
           "-postScript", "decompile_function.py", out_json, function,
           "-deleteProject"]
    rc, out, serr = _run(cmd, config.TIMEOUT_TRIAGE)
    data = None
    try:
        with open(out_json) as f:
            data = json.load(f)
    except Exception:
        data = None
    finally:
        shutil.rmtree(proj, ignore_errors=True)
    if data is None:
        return json.dumps({"error": "Ghidra lieferte kein JSON", "rc": rc, "stderr": serr[-600:]})
    return json.dumps(data, ensure_ascii=False)


@mcp.tool()
def list_symbols(path: str, kind: str = "functions") -> str:
    """Schnelles Inventar via r2/rizin (ohne Ghidra, Sekunden). kind = 'functions' | 'imports' | 'strings'.
    Gut für den ersten Überblick / um Ziele für decompile_function zu finden. READ-ONLY."""
    err = _validate(path)
    if err:
        return json.dumps({"error": err})
    kind = (kind or "functions").lower()
    pipe = {"functions": "aa;aflj", "imports": "iij", "strings": "izj"}.get(kind)
    if pipe is None:
        return json.dumps({"error": "kind muss functions|imports|strings sein, war: %s" % kind})
    out, e = _r2(path, pipe)
    if e:
        return json.dumps({"error": e})
    try:
        arr = json.loads(out.strip() or "[]")
    except Exception:
        return json.dumps({"error": "r2-JSON-Parse fehlgeschlagen", "raw": out[:600]})
    if kind == "functions":
        arr = [{"name": f.get("name"), "offset": hex(f.get("offset", 0)), "size": f.get("size"),
                "nargs": f.get("nargs")} for f in arr][:400]
    elif kind == "imports":
        arr = [{"name": i.get("name"), "type": i.get("type"), "plt": i.get("plt")} for i in arr][:400]
    else:
        arr = [{"string": (s.get("string") or "")[:200], "vaddr": hex(s.get("vaddr", 0))}
               for s in arr][:400]
    return json.dumps({"kind": kind, "count": len(arr), "items": arr}, ensure_ascii=False)


@mcp.tool()
def analyze_apk(path: str, arch: str = "", sandbox: bool = True) -> str:
    """Android-APK-Triage: zieht native Libs (lib/*/*.so) und jagt jede durch re_triage.py
    (Ghidra-Dekompilat -> capa/floss -> Sink-Rang). Deckt die native Schicht ab, die jadx/apktool nicht sehen.
    'arch' optional, z.B. 'arm64-v8a' (sonst alle). 'sandbox' (Default True): läuft in der bwrap-Kammer
    (keine Ausführung, kein Netz). READ-ONLY, entpackt nur, führt NICHTS aus der APK aus. Eigene / in-scope APKs."""
    err = _validate(path, want_suffix=".apk")
    if err:
        return json.dumps({"error": err})
    if not os.path.exists(config.APK_TRIAGE):
        return json.dumps({"error": "apk_native_triage.sh nicht gefunden: %s" % config.APK_TRIAGE})
    use_sbx = sandbox and config.tool_available("bwrap")
    outdir = tempfile.mkdtemp(prefix="remcp_apk_")
    base = ["bash", str(config.SANDBOX), "--apk"] if use_sbx else ["bash", str(config.APK_TRIAGE)]
    cmd = base + [path, "--out", outdir] + (["--arch", arch] if arch else [])
    rc, out, serr = _run(cmd, config.TIMEOUT_SANDBOX)
    reports = []
    try:
        for root, _dirs, files in os.walk(outdir):
            for fn in files:
                if fn.endswith(".json"):
                    try:
                        with open(os.path.join(root, fn)) as f:
                            j = json.load(f)
                        reports.append({"lib": fn, "inventory_count": j.get("inventory_count"),
                                        "top": (j.get("ranked") or [])[:10], "capa": j.get("capa")})
                    except Exception:
                        continue
    finally:
        shutil.rmtree(outdir, ignore_errors=True)
    return json.dumps({"apk": os.path.basename(path), "sandboxed": use_sbx,
                       "native_libs_analyzed": len(reports),
                       "reports": reports, "rc": rc,
                       "stderr": serr[-400:] if rc != 0 else ""}, ensure_ascii=False)


def main() -> None:
    log.info("re-mcp startet (Ghidra=%s, re_triage=%s)", config.GHIDRA_HEADLESS, config.RE_TRIAGE)
    mcp.run()


if __name__ == "__main__":
    main()
