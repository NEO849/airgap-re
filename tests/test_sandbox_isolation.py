"""
Isolations-Beweis-Tests — belegen die messbaren Security-Claims des Projekts.

Diese Tests sind der Kern des Projekt-Versprechens: die Sandbox-Garantien sind
nicht behauptet, sondern in CI nachgewiesen. Sie laufen überall, wo bwrap
(bubblewrap) installiert ist (im CI via `apt-get install -y bubblewrap`).
"""
import os
import shutil
import subprocess
import sys

import pytest

BWRAP = shutil.which("bwrap")
pytestmark = pytest.mark.skipif(BWRAP is None, reason="bwrap (bubblewrap) nicht installiert")

_LIB64 = ["--ro-bind", "/lib64", "/lib64"] if os.path.exists("/lib64") else []
_BASE = [
    "bwrap", "--unshare-all", "--die-with-parent",
    "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
    *_LIB64, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
]


def _run_in_chamber(code: str) -> str:
    r = subprocess.run(_BASE + ["/usr/bin/python3", "-c", code],
                       capture_output=True, text=True, timeout=60)
    return (r.stdout or "") + (r.stderr or "")


def test_no_network_egress():
    """In der Kammer ist JEDER ausgehende Verbindungsversuch strukturell unmöglich."""
    out = _run_in_chamber(
        "import socket\n"
        "try:\n"
        "    socket.setdefaulttimeout(3)\n"
        "    socket.create_connection(('1.1.1.1', 53))\n"
        "    print('REACHED')\n"
        "except Exception:\n"
        "    print('BLOCKED')\n"
    )
    assert "BLOCKED" in out and "REACHED" not in out


def test_host_filesystem_readonly():
    """Host-Pfade sind read-only gebunden — Schreiben MUSS scheitern."""
    out = _run_in_chamber(
        "try:\n"
        "    open('/usr/_remcp_probe', 'w').write('x')\n"
        "    print('WROTE')\n"
        "except Exception:\n"
        "    print('READONLY')\n"
    )
    assert "READONLY" in out and "WROTE" not in out


def test_no_host_network_interfaces():
    """Die Netz-Namespace der Kammer enthält nur loopback — kein Weg nach draußen."""
    out = _run_in_chamber(
        "import socket\n"
        "ifaces = socket.if_nameindex()\n"
        "print(sorted(n for _, n in ifaces))\n"
    )
    # nur 'lo' (oder leer) — keine echten Interfaces
    assert "eth" not in out and "wlan" not in out and "en" not in out.replace("index", "")


@pytest.mark.skipif(
    shutil.which("systemd-run") is None
    or subprocess.run(["systemd-run", "--user", "--scope", "true"],
                      capture_output=True).returncode != 0,
    reason="systemd-run --user scope nicht nutzbar (cgroup-Delegation fehlt)",
)
def test_cgroup_memory_cap_enforced():
    """Mit cgroup-MemoryMax wird ein Speicher-Fresser vom Kernel gekillt (OOM), nicht der Host."""
    code = "b = bytearray()\n\nwhile True:\n    b += bytearray(10_000_000)\n"
    r = subprocess.run(
        ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=64M", "-p", "MemorySwapMax=0"]
        + _BASE + ["/usr/bin/python3", "-c", code],
        capture_output=True, text=True, timeout=60,
    )
    # Der Prozess wird gekillt (OOM) -> non-zero exit; der Testlauf selbst überlebt.
    assert r.returncode != 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
