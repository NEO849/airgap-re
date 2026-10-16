#!/usr/bin/env python3
"""
run_benchmark.py — misst die objektiven Kennzahlen, auf die README und der
Antwort-Post sich berufen. Keine Behauptung ohne Messung hier.

Erzeugt benchmark/REPORT.md. Alle Zahlen stammen aus DIESEM Lauf auf DIESEM Repo;
REA-Vergleichszahlen sind als extern-gemessen / Quelle markiert (nicht hier erhoben).

  python3 benchmark/run_benchmark.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import tomllib

REPO = Path(__file__).resolve().parent.parent
OWN_CODE_DIRS = [REPO / "re_mcp", REPO / "engine"]
CODE_SUFFIXES = {".py", ".sh"}


def count_own_code() -> dict:
    files, loc = 0, 0
    for d in OWN_CODE_DIRS:
        for p in d.rglob("*"):
            if p.suffix in CODE_SUFFIXES and "__pycache__" not in p.parts:
                files += 1
                loc += sum(1 for _ in p.open("rb"))
    return {"own_code_files": files, "own_code_loc": loc}


def count_direct_deps() -> int:
    with (REPO / "pyproject.toml").open("rb") as f:
        data = tomllib.load(f)
    return len(data["project"].get("dependencies", []))


def count_transitive_deps() -> int | None:
    """Ehrliche Zahl: der volle Laufzeit-Abschluss von 'mcp' (nicht nur die direkte Deklaration)."""
    import importlib.metadata as md
    import re as _re
    try:
        seen: set[str] = set()
        stack = ["mcp"]
        while stack:
            name = stack.pop().lower().replace("_", "-")
            if name in seen:
                continue
            seen.add(name)
            try:
                reqs = md.requires(name) or []
            except md.PackageNotFoundError:
                continue
            for r in reqs:
                # Extras/Marker ausblenden; nur Pflicht-Laufzeit-Deps zählen
                if "extra ==" in r or "; extra" in r:
                    continue
                m = _re.match(r"^([A-Za-z0-9_.\-]+)", r.strip())
                if m:
                    stack.append(m.group(1))
        seen.discard("mcp")
        return len(seen)
    except Exception:
        return None


def repo_file_count() -> int:
    r = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return len([x for x in r.stdout.splitlines() if x.strip()])
    # Fallback ohne git: zähle versionierbare Dateien grob
    return sum(1 for p in REPO.rglob("*")
               if p.is_file() and "__pycache__" not in p.parts and ".git" not in p.parts)


def _chamber(code: str):
    if not shutil.which("bwrap"):
        return None
    lib64 = ["--ro-bind", "/lib64", "/lib64"] if os.path.exists("/lib64") else []
    cmd = ["bwrap", "--unshare-all", "--die-with-parent",
           "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
           *lib64, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
           "/usr/bin/python3", "-c", code]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def isolation_checks() -> dict:
    if not shutil.which("bwrap"):
        return {"available": False}
    egress = _chamber("import socket\n"
                      "try:\n socket.setdefaulttimeout(3); socket.create_connection(('1.1.1.1',53)); print('REACHED')\n"
                      "except Exception: print('BLOCKED')\n")
    rdonly = _chamber("try:\n open('/usr/_p','w').write('x'); print('WROTE')\n"
                      "except Exception: print('READONLY')\n")
    return {
        "available": True,
        "no_network_egress": "PASS" if "BLOCKED" in (egress.stdout or "") else "FAIL",
        "host_filesystem_readonly": "PASS" if "READONLY" in (rdonly.stdout or "") else "FAIL",
    }


def determinism_check() -> dict:
    """Zwei Läufe eines statischen Inventars über dasselbe Mini-ELF -> identischer Hash?"""
    cc = shutil.which("cc") or shutil.which("gcc")
    r2 = shutil.which("r2") or shutil.which("rizin")
    if not cc or not r2:
        return {"available": False, "reason": "cc oder r2/rizin fehlt"}
    import tempfile
    d = tempfile.mkdtemp(prefix="remcp_bench_")
    try:
        src = Path(d) / "t.c"
        src.write_text(
            "#include <string.h>\n"
            "int f(char*s){char b[8];strcpy(b,s);return (int)b[0];}\n"
            'int main(){return f("x");}\n'
        )
        binp = Path(d) / "t"
        if subprocess.run([cc, "-O0", str(src), "-o", str(binp)], capture_output=True).returncode != 0:
            return {"available": False, "reason": "Kompilierung fehlgeschlagen"}
        hashes = []
        for _ in range(2):
            out = subprocess.run([r2, "-q", "-c", "aa;aflj", str(binp)],
                                 capture_output=True, text=True, timeout=120).stdout
            hashes.append(hashlib.sha256(out.encode()).hexdigest())
        return {"available": True, "deterministic": hashes[0] == hashes[1], "sha256": hashes[0][:16]}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    m = {}
    m.update(count_own_code())
    m["direct_dependencies"] = count_direct_deps()
    m["transitive_dependencies"] = count_transitive_deps()
    m["repo_tracked_files"] = repo_file_count()
    m["isolation"] = isolation_checks()
    m["determinism"] = determinism_check()
    m["measured_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    m["python"] = sys.version.split()[0]

    iso = m["isolation"]
    det = m["determinism"]
    iso_line = (f"egress={iso.get('no_network_egress','-')}, "
                f"host-ro={iso.get('host_filesystem_readonly','-')}" if iso.get("available")
                else "bwrap nicht verfügbar")
    det_line = ("deterministisch" if det.get("deterministic") else
                ("nicht deterministisch" if det.get("available") else f"n/a ({det.get('reason','')})"))

    report = f"""# Benchmark-Report — sandboxed-re-mcp

> Selbst-gemessen am {m['measured_at']} (Python {m['python']}) durch `benchmark/run_benchmark.py`.
> Jede Zahl stammt aus diesem Lauf auf diesem Repo. Reproduzierbar: Skript erneut ausführen.

## Objektive Kennzahlen (dieses Repo)

| Metrik | Wert |
|---|---|
| Eigener Code (Dateien) | {m['own_code_files']} |
| Eigener Code (Zeilen) | {m['own_code_loc']} |
| Direkte Laufzeit-Abhängigkeit | {m['direct_dependencies']} (mcp, gepinnt) |
| Transitive Laufzeit-Deps (voller Abschluss von mcp) | {m['transitive_dependencies']} |
| Versionierte Dateien gesamt | {m['repo_tracked_files']} |
| Isolations-Selbsttest | {iso_line} |
| Determinismus (statisches Inventar, 2 Läufe) | {det_line} |

## Sicherheits-Garantien (in CI bewiesen, nicht behauptet)

- **Kein Egress:** `bwrap --unshare-all` entfernt die Netz-Namespace — ausgehende
  Verbindungen sind strukturell unmöglich. Beleg: `tests/test_sandbox_isolation.py::test_no_network_egress`.
- **Host read-only:** Host-Pfade sind read-only gebunden; Schreiben scheitert.
  Beleg: `::test_host_filesystem_readonly`.
- **Ressourcen-Cap:** cgroup `MemoryMax` killt einen Speicher-Fresser (OOM), nicht den Host.
  Beleg: `::test_cgroup_memory_cap_enforced`.
- **Ziel wird nie ausgeführt:** rein statische Pipeline; das Sample wird als read-only
  Datei analysiert, nie gestartet.

## Einordnung zu REA (morluto/rea) — Quellen extern

Diese Zeilen sind NICHT hier gemessen, sondern dem öffentlichen REA-Repo / dessen README
und unserer Tool-Prüfung (2026-10-12) entnommen. Sie dienen der ehrlichen Einordnung:

| Dimension | sandboxed-re-mcp | REA (morluto/rea) |
|---|---|---|
| Tool-Breite | nativ + APK-nativ (fokussiert) | sehr breit (nativ/web/firmware/netz/WASM/…) — **REA führt** |
| Untrusted-Isolation | bwrap no-net + cgroup, nie ausgeführt | **kein Sandbox**; Laufzeit mit User-Rechten |
| Laufzeit-Deps | {m['direct_dependencies']} dir./{m['transitive_dependencies']} trans. | ~35 npm (Vet, andere Basis) |
| Setup-Fußabdruck | lokal, schreibt nicht in Agent-Config | `npx … setup` schreibt in `~/.claude` |
| Auditierbarkeit | {m['own_code_loc']} Zeilen eigener Code | großer Baum (per Vet ~2255 Dateien) |

> Fazit ehrlich: REA gewinnt bei Breite. sandboxed-re-mcp gewinnt dort, wo es am meisten
> zählt, wenn man **fremde/bösartige** Binaries anfasst: Isolation, Auditierbarkeit, geringer Fußabdruck.
"""
    (REPO / "benchmark" / "REPORT.md").write_text(report)
    print(json.dumps(m, indent=2, ensure_ascii=False))
    print("\n-> benchmark/REPORT.md geschrieben")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
