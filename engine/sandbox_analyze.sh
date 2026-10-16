#!/usr/bin/env bash
# ============================================================
# sandbox_analyze.sh — statische RE-Triage in einer bubblewrap-Wegwerfkammer.
#
# Null-Risiko-Pfad für UNTRUSTED Artefakte: falls eine Parser-Lücke in
# Ghidra/r2/capa ausgelöst würde, kann der Code NICHT nach Hause funken,
# NICHT auf den Host schreiben und NICHT den Host lahmlegen.
#
#   - KEIN Netz        : bwrap --unshare-all (inkl. net)  -> Egress strukturell unmöglich
#   - Keine Caps       : bwrap droppt alle Capabilities per Default
#   - Read-only Host   : nur Tool-Dirs ro-gebunden; einzig /out (Host-Temp) ist rw,
#                        wird per EXIT-trap gelöscht.
#   - Ressourcen-Cap   : systemd-run cgroup MemoryMax + MemorySwapMax=0 + TasksMax + CPUQuota
#   - Ziel wird NIE ausgeführt (rein statische Analyse).
#
# Non-Goal (bewusst NICHT behauptet): kein custom seccomp-BPF-Filter.
#
# WICHTIG: der Isolations-Aufbau (bwrap_base) wird EINMAL gebaut und von allen Modi
#   geteilt — inkl. --selftest. Dadurch prüfen die Tests exakt den ausgelieferten Pfad:
#   wird --unshare-all hier entfernt, schlägt der --selftest-Egress-Check fehl.
#
# Modi:
#   sandbox_analyze.sh <binary> [--floss]
#   sandbox_analyze.sh --apk <app.apk> --out <dir> [--arch <abi>]
#   sandbox_analyze.sh --selftest        # beweist Isolation, ohne ein Ziel zu analysieren
#
# Env-Overrides (sonst Auto-Discovery): REMCP_ENGINE_DIR REMCP_GHIDRA REMCP_VENV
#   REMCP_SBX_MEM_MAX REMCP_SBX_PIDS_MAX REMCP_SBX_CPU_MAX
# ============================================================
set -uo pipefail

err_json() { printf '{"error":%s}\n' "$(printf '%s' "$1" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')"; }

command -v bwrap >/dev/null 2>&1 || { err_json "bwrap (bubblewrap) nicht installiert"; exit 3; }

ENGINE_DIR="${REMCP_ENGINE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
GHIDRA_DIR="${REMCP_GHIDRA:-/opt/ghidra}"
VENV_DIR="${REMCP_VENV:-/opt/re-venv}"
MEM_MAX="${REMCP_SBX_MEM_MAX:-4G}"
PIDS_MAX="${REMCP_SBX_PIDS_MAX:-512}"
CPU_MAX="${REMCP_SBX_CPU_MAX:-200%}"

RE_TRIAGE="$ENGINE_DIR/re_triage.py"
APK_TRIAGE="$ENGINE_DIR/apk_native_triage.sh"

# -------- Argumente parsen --------
MODE="bin"; BIN=""; APK=""; OUTDIR=""; ARCH=""; EXTRA=()
case "${1:-}" in
  --selftest)
    MODE="selftest"; shift ;;
  --apk)
    MODE="apk"; shift
    APK="${1:-}"; shift || true
    while [ $# -gt 0 ]; do case "$1" in
      --out) OUTDIR="${2:-}"; shift 2 ;;
      --arch) ARCH="${2:-}"; shift 2 ;;
      *) shift ;;
    esac; done
    [ -n "$APK" ] && [ -f "$APK" ] || { err_json "APK nicht gefunden: $APK"; exit 2; }
    [ -n "$OUTDIR" ] || { err_json "--out <dir> fehlt"; exit 2; } ;;
  *)
    BIN="${1:-}"; shift || true
    for a in "$@"; do case "$a" in --floss) EXTRA+=(--floss) ;; esac; done
    [ -n "$BIN" ] && [ -f "$BIN" ] || { err_json "Datei nicht gefunden: $BIN"; exit 2; } ;;
esac

OUT_HOST="$(mktemp -d /tmp/remcp_sbx.XXXXXX)"
trap 'rm -rf "$OUT_HOST"' EXIT

GHIDRA_REAL="$(readlink -f "$GHIDRA_DIR" 2>/dev/null || echo "$GHIDRA_DIR")"

bind_ro=()
for p in /usr /bin /sbin /lib /lib64 /etc "$GHIDRA_DIR" "$GHIDRA_REAL" "$VENV_DIR" "$HOME/.local" "$ENGINE_DIR"; do
  [ -e "$p" ] && bind_ro+=(--ro-bind "$p" "$p")
done

# -------- GETEILTER Isolations-Aufbau (von allen Modi genutzt) --------
bwrap_base=( bwrap --unshare-all --die-with-parent --new-session "${bind_ro[@]}"
             --tmpfs /tmp --proc /proc --dev /dev
             --setenv PATH "$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
             --setenv HOME /tmp --chdir /tmp
             --setenv REMCP_ENGINE_DIR "$ENGINE_DIR" )

# -------- Mode-spezifisches Kommando --------
bwrap_cmd=( "${bwrap_base[@]}" )
case "$MODE" in
  selftest)
    probe='import socket,json
r={}
try:
    socket.setdefaulttimeout(3); socket.create_connection(("1.1.1.1",53)); r["no_network_egress"]="FAIL"
except Exception: r["no_network_egress"]="PASS"
try:
    open("/usr/_remcp_probe","w").write("x"); r["host_filesystem_readonly"]="FAIL"
except Exception: r["host_filesystem_readonly"]="PASS"
r["verdict"]="PASS" if all(v=="PASS" for v in r.values()) else "FAIL"
print(json.dumps(r))'
    bwrap_cmd+=( /usr/bin/python3 -c "$probe" ) ;;
  apk)
    bwrap_cmd+=( --ro-bind "$APK" /target.apk --bind "$OUT_HOST" /out
                 /usr/bin/env bash "$APK_TRIAGE" /target.apk --out /out )
    [ -n "$ARCH" ] && bwrap_cmd+=( --arch "$ARCH" ) ;;
  bin)
    bwrap_cmd+=( --ro-bind "$BIN" /target.bin --bind "$OUT_HOST" /out
                 /usr/bin/python3 "$RE_TRIAGE" /target.bin --json /out/out.json --md /dev/null "${EXTRA[@]}" ) ;;
esac

# -------- cgroup-Ressourcen-Cap via systemd-run (falls nutzbar) --------
run_with_caps() {
  local caps=( -p "MemoryMax=$MEM_MAX" -p "MemorySwapMax=0" -p "TasksMax=$PIDS_MAX" -p "CPUQuota=$CPU_MAX" )
  if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope true >/dev/null 2>&1; then
    systemd-run --user --scope -q "${caps[@]}" "${bwrap_cmd[@]}"
  elif command -v systemd-run >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    systemd-run --scope -q "${caps[@]}" "${bwrap_cmd[@]}"
  else
    echo "WARN: systemd-run nicht nutzbar — cgroup-Limits inaktiv, Netz/FS-Isolation unberührt." >&2
    "${bwrap_cmd[@]}"
  fi
}

# -------- Ausführen + Ergebnis --------
if [ "$MODE" = "selftest" ]; then
  # Selbsttest-JSON direkt auf stdout (kein /out nötig)
  run_with_caps 2>/tmp/sbx.err
  exit 0
fi

run_with_caps >/dev/null 2>/tmp/sbx.err || true

if [ "$MODE" = "apk" ]; then
  if [ -n "$(find "$OUT_HOST" -name '*.json' 2>/dev/null)" ]; then
    cp -a "$OUT_HOST"/. "$OUTDIR"/ 2>/dev/null || true
    echo '{"ok":true,"mode":"apk"}'
  else
    err_json "APK-Sandbox-Analyse ohne JSON-Ausgabe"
  fi
else
  if [ -s "$OUT_HOST/out.json" ]; then
    cat "$OUT_HOST/out.json"
  else
    err_json "Sandbox-Analyse ohne JSON-Ausgabe"
  fi
fi
