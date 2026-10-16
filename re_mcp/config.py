#!/usr/bin/env python3
"""
config.py — zentrale, verschiebbare Konfiguration für sandboxed-re-mcp.

Grundsatz: KEINE hartkodierten Host-Pfade im Code. Jeder Pfad wird
  1. per Umgebungsvariable (REMCP_*) gesetzt, sonst
  2. automatisch entdeckt (PATH / übliche Installationsorte), sonst
  3. auf einen klar benannten Default gesetzt.

So läuft der Server auf jedem Host, nicht nur auf dem Entwicklungs-System.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

# ---------------------------------------------------------------------------
# Verzeichnis-Layout (relativ zum Paket, nicht zum Host)
# ---------------------------------------------------------------------------
PKG_DIR = Path(__file__).resolve().parent          # .../re_mcp
REPO_ROOT = PKG_DIR.parent                          # Repo-Wurzel
ENGINE_DIR = Path(os.environ.get("REMCP_ENGINE_DIR", REPO_ROOT / "engine"))

RE_TRIAGE = ENGINE_DIR / "re_triage.py"
APK_TRIAGE = ENGINE_DIR / "apk_native_triage.sh"
SANDBOX = ENGINE_DIR / "sandbox_analyze.sh"
GHIDRA_SCRIPTS = ENGINE_DIR / "ghidra_scripts"


def _discover(env_key: str, candidates: list[str], names: list[str]) -> str:
    """Env-Override > PATH-Lookup > erster existierender Kandidat > erster Name."""
    env_val = os.environ.get(env_key)
    if env_val:
        return env_val
    for name in names:
        hit = shutil.which(name)
        if hit:
            return hit
    for cand in candidates:
        if os.path.exists(cand):
            return cand
    return candidates[0] if candidates else (names[0] if names else "")


# ---------------------------------------------------------------------------
# Externe Werkzeuge (auto-discovered, env-überschreibbar)
# ---------------------------------------------------------------------------
GHIDRA_HEADLESS = _discover(
    "REMCP_GHIDRA_HEADLESS",
    ["/opt/ghidra/support/analyzeHeadless",
     "/usr/share/ghidra/support/analyzeHeadless"],
    ["ghidra-headless", "analyzeHeadless"],
)

# Python-Interpreter des angr-venv (optional; Fallback = kein symbolischer Lauf)
VENV_PY = _discover(
    "REMCP_VENV_PY",
    ["/opt/re-venv/bin/python", str(REPO_ROOT / ".venv" / "bin" / "python")],
    [],
)

# ---------------------------------------------------------------------------
# Laufzeit-Parameter
# ---------------------------------------------------------------------------
LOG_PATH = os.environ.get("REMCP_LOG", str(REPO_ROOT / "re-mcp.log"))
MAX_BYTES = int(os.environ.get("REMCP_MAX_BYTES", 1_000_000_000))      # 1 GB
TIMEOUT_TRIAGE = int(os.environ.get("REMCP_TIMEOUT_TRIAGE", 2400))
TIMEOUT_SANDBOX = int(os.environ.get("REMCP_TIMEOUT_SANDBOX", 2700))

# Sandbox-Ressourcen-Obergrenzen (messbar; via tests/test_sandbox_isolation.py belegt)
SBX_MEM_MAX = os.environ.get("REMCP_SBX_MEM_MAX", "4G")     # cgroup MemoryMax
SBX_PIDS_MAX = os.environ.get("REMCP_SBX_PIDS_MAX", "512")  # cgroup TasksMax
SBX_CPU_MAX = os.environ.get("REMCP_SBX_CPU_MAX", "200%")   # cgroup CPUQuota (2 Kerne)


def tool_available(name: str) -> bool:
    return bool(shutil.which(name))


def ghidra_available() -> bool:
    return os.path.exists(GHIDRA_HEADLESS)
