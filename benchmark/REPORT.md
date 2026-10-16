# Benchmark-Report — sandboxed-re-mcp

> Selbst-gemessen am 2026-10-16 16:49 UTC (Python 3.12.3) durch `benchmark/run_benchmark.py`.
> Jede Zahl stammt aus diesem Lauf auf diesem Repo. Reproduzierbar: Skript erneut ausführen.

## Objektive Kennzahlen (dieses Repo)

| Metrik | Wert |
|---|---|
| Eigener Code (Dateien) | 8 |
| Eigener Code (Zeilen) | 1196 |
| Direkte Laufzeit-Abhängigkeit | 1 (mcp, gepinnt) |
| Transitive Laufzeit-Deps (voller Abschluss von mcp) | 27 |
| Versionierte Dateien gesamt | 22 |
| Isolations-Selbsttest | egress=PASS, host-ro=PASS |
| Determinismus (statisches Inventar, 2 Läufe) | deterministisch |

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
| Laufzeit-Deps | 1 dir./27 trans. | ~35 npm (Vet, andere Basis) |
| Setup-Fußabdruck | lokal, schreibt nicht in Agent-Config | `npx … setup` schreibt in `~/.claude` |
| Auditierbarkeit | 1196 Zeilen eigener Code | großer Baum (per Vet ~2255 Dateien) |

> Fazit ehrlich: REA gewinnt bei Breite. sandboxed-re-mcp gewinnt dort, wo es am meisten
> zählt, wenn man **fremde/bösartige** Binaries anfasst: Isolation, Auditierbarkeit, geringer Fußabdruck.
