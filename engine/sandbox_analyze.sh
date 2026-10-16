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
#   - Read-only Host   : nur Tool-Dirs ro-gebunden; Ziel ro unter /target.bin
#   - Schreiben nur     : tmpfs /tmp + eine gebundene /out (Host-Temp, danach gelöscht)
#   - Ressourcen-Cap   : systemd-run cgroup MemoryMax/TasksMax/CPUQuota (falls verfügbar)
#   - Ziel wird NIE ausgeführt (rein statische Analyse).
#
# Non-Goal (bewusst NICHT behauptet): kein custom seccomp-BPF-Filter — bwrap setzt
#   keinen per Default; ein falscher Filter würde Ghidra/Python brechen. Die Isolation
#   stützt sich auf Namespaces (unshare-all) + cap-drop + read-only-bind + cgroup.
#
# Modi:
#   sandbox_analyze.sh <binary> [--floss]            # einzelnes natives Binary
#   sandbox_analyze.sh --apk <app.apk> --out <dir> [--arch <abi>]   # APK native libs
#
# Env-Overrides (sonst Auto-Discovery):
#   REMCP_ENGINE_DIR  Verzeichnis mit re_triage.py / apk_native_triage.sh / ghidra_scripts
#   REMCP_GHIDRA      Ghidra-Installationsverzeichnis (Default: /opt/ghidra)
#   REMCP_VENV        angr-venv-Verzeichnis           (Default: /opt/re-venv)
#   REMCP_SBX_MEM_MAX / REMCP_SBX_PIDS_MAX / REMCP_SBX_CPU_MAX  cgroup-Limits
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
APK_MODE=0; BIN=""; APK=""; OUTDIR=""; ARCH=""; EXTRA=()
if [ "${1:-}" = "--apk" ]; then
  APK_MODE=1; shift
  APK="${1:-}"; shift || true
  while [ $# -gt 0 ]; do case "$1" in
    --out) OUTDIR="${2:-}"; shift 2 ;;
    --arch) ARCH="${2:-}"; shift 2 ;;
    *) shift ;;
  esac; done
  [ -n "$APK" ] && [ -f "$APK" ] || { err_json "APK nicht gefunden: $APK"; exit 2; }
  [ -n "$OUTDIR" ] || { err_json "--out <dir> fehlt"; exit 2; }
else
  BIN="${1:-}"; shift || true
  for a in "$@"; do case "$a" in --floss) EXTRA+=(--floss) ;; esac; done
  [ -n "$BIN" ] && [ -f "$BIN" ] || { err_json "Datei nicht gefunden: $BIN"; exit 2; }
fi

OUT_HOST="$(mktemp -d /tmp/remcp_sbx.XXXXXX)"
trap 'rm -rf "$OUT_HOST"' EXIT

GHIDRA_REAL="$(readlink -f "$GHIDRA_DIR" 2>/dev/null || echo "$GHIDRA_DIR")"

bind_ro=()
for p in /usr /bin /sbin /lib /lib64 /etc "$GHIDRA_DIR" "$GHIDRA_REAL" "$VENV_DIR" "$HOME/.local" "$ENGINE_DIR"; do
  [ -e "$p" ] && bind_ro+=(--ro-bind "$p" "$p")
done

# -------- bwrap-Kommando zusammenbauen --------
bwrap_cmd=( bwrap --unshare-all --die-with-parent --new-session "${bind_ro[@]}" )
if [ "$APK_MODE" -eq 1 ]; then
  bwrap_cmd+=( --ro-bind "$APK" /target.apk --bind "$OUT_HOST" /out )
  payload=( /usr/bin/env bash "$APK_TRIAGE" /target.apk --out /out )
  [ -n "$ARCH" ] && payload+=( --arch "$ARCH" )
else
  bwrap_cmd+=( --ro-bind "$BIN" /target.bin --bind "$OUT_HOST" /out )
  payload=( /usr/bin/python3 "$RE_TRIAGE" /target.bin --json /out/out.json --md /dev/null "${EXTRA[@]}" )
fi
bwrap_cmd+=( --tmpfs /tmp --proc /proc --dev /dev
             --setenv PATH "$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
             --setenv HOME /tmp --chdir /tmp
             --setenv REMCP_ENGINE_DIR "$ENGINE_DIR"
             "${payload[@]}" )

# -------- cgroup-Ressourcen-Cap via systemd-run (falls nutzbar) --------
run_with_caps() {
  if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope true >/dev/null 2>&1; then
    systemd-run --user --scope -q \
      -p "MemoryMax=$MEM_MAX" -p "TasksMax=$PIDS_MAX" -p "CPUQuota=$CPU_MAX" \
      "${bwrap_cmd[@]}"
  elif command -v systemd-run >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    systemd-run --scope -q \
      -p "MemoryMax=$MEM_MAX" -p "TasksMax=$PIDS_MAX" -p "CPUQuota=$CPU_MAX" \
      "${bwrap_cmd[@]}"
  else
    # Fallback ohne cgroup-Cap: Isolation (Netz/Caps/FS) bleibt voll erhalten.
    echo "WARN: systemd-run nicht nutzbar — cgroup-Limits inaktiv, Netz/FS-Isolation unberührt." >&2
    "${bwrap_cmd[@]}"
  fi
}

run_with_caps >/dev/null 2>/tmp/sbx.err || true

# -------- Ergebnis einsammeln --------
if [ "$APK_MODE" -eq 1 ]; then
  # apk_native_triage.sh schreibt je .so einen json-Report nach /out -> Host-OUT_HOST
  if [ -n "$(find "$OUT_HOST" -name '*.json' 2>/dev/null)" ]; then
    # Reports an den vom Server erwarteten outdir übergeben
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
