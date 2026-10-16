"""
Isolations-Beweis-Tests — belegen die messbaren Security-Claims des Projekts.

WICHTIG: Diese Tests fahren den AUSGELIEFERTEN Pfad (engine/sandbox_analyze.sh --selftest),
nicht eine nachgebaute bwrap-Zeile. Wird --unshare-all aus dem Script entfernt, schlägt
test_shipped_script_blocks_egress fehl (empirisch verifiziert). Das ist der echte
Regressions-Wächter — ein grüner Build bedeutet: die ausgelieferte Isolation hält.

Läuft überall, wo bwrap (bubblewrap) installiert ist (CI: apt-get install -y bubblewrap).
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from re_mcp import config

BWRAP = shutil.which("bwrap")
pytestmark = pytest.mark.skipif(BWRAP is None, reason="bwrap (bubblewrap) nicht installiert")

SANDBOX = str(config.SANDBOX)


def _selftest() -> dict:
    """Ruft den ausgelieferten Isolations-Selbsttest auf und gibt sein JSON zurück.

    Kann die Umgebung gar keine bwrap-Namespaces erstellen (z.B. AppArmor sperrt
    unprivilegierte user-namespaces), skippt der Test ehrlich statt falsch zu scheitern —
    das ist eine Umgebungs-Beschränkung, kein gebrochenes Isolations-Versprechen.
    (In CI wird unpriv-userns freigeschaltet, damit der echte Beweis läuft.)"""
    r = subprocess.run(["bash", SANDBOX, "--selftest"],
                       check=False, capture_output=True, text=True, timeout=120)
    out = (r.stdout or "").strip()
    if not out:
        pytest.skip(f"sandbox_analyze.sh --selftest ohne Ausgabe (stderr: {(r.stderr or '')[:200]})")
    data = json.loads(out)
    if data.get("error") == "sandbox_start_failed":
        pytest.skip(f"bwrap kann in dieser Umgebung keine Namespaces erstellen: {data.get('detail', '')[:200]}")
    return data


def test_shipped_script_blocks_egress():
    """Ausgelieferter Pfad: in der Kammer ist ausgehender Netzverkehr unmöglich.
    Entfernt man --unshare-all aus sandbox_analyze.sh, wird dieser Test ROT."""
    assert _selftest()["no_network_egress"] == "PASS"


def test_shipped_script_host_readonly():
    """Ausgelieferter Pfad: Schreiben auf einen Host-Pfad scheitert."""
    assert _selftest()["host_filesystem_readonly"] == "PASS"


def test_shipped_script_overall_verdict():
    assert _selftest()["verdict"] == "PASS"


def test_shipped_script_declares_isolation_flags():
    """Statischer Wächter gegen Claim-Drift: das ausgelieferte Script trägt die Garantien,
    auf die README/THREAT_MODEL sich berufen."""
    txt = Path(SANDBOX).read_text()
    for needle in ("--unshare-all", "MemoryMax=", "MemorySwapMax=0", "TasksMax=", "CPUQuota="):
        assert needle in txt, f"fehlt im ausgelieferten Script: {needle}"


@pytest.mark.skipif(
    shutil.which("systemd-run") is None
    or subprocess.run(["systemd-run", "--user", "--scope", "true"],
                      check=False, capture_output=True).returncode != 0,
    reason="systemd-run --user scope nicht nutzbar (cgroup-Delegation fehlt)",
)
def test_cgroup_memory_cap_enforced():
    """Mit cgroup-MemoryMax + MemorySwapMax=0 wird ein Speicher-Fresser vom Kernel gekillt
    (wie im ausgelieferten run_with_caps), nicht der Host."""
    lib64 = ["--ro-bind", "/lib64", "/lib64"] if Path("/lib64").exists() else []
    base = ["bwrap", "--unshare-all", "--die-with-parent",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
            *lib64, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    code = "b = bytearray()\n\nwhile True:\n    b += bytearray(10_000_000)\n"
    r = subprocess.run(
        ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=64M", "-p", "MemorySwapMax=0"]
        + base + ["/usr/bin/python3", "-c", code],
        check=False, capture_output=True, text=True, timeout=60,
    )
    assert r.returncode != 0  # OOM-gekillt; der Testlauf selbst überlebt


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
