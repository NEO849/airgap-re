#!/usr/bin/env bash
# ============================================================
# apk_native_triage.sh — Auto-Stage: APK → native .so → re_triage.py
#
# Schließt die Lücke: /mobile-re Phase 2 deckt smali/Java (jadx/apktool) ab, aber
# NICHT die nativen Libs (lib/*/*.so = ELF), wo die interessante Krypto/Auth/
# Parsing-Logik oft liegt. Dieser Wrapper zieht die .so aus der APK und jagt jede
# durch re_triage.py (Ghidra-Dekompilat → capa/floss → Sink-Rank → optional angr).
#
# READ-ONLY: entpackt nur, führt NICHTS aus der APK aus. Eigene/in-scope APKs.
#
# NUTZUNG:  apk_native_triage.sh <app.apk> [--symbolic] [--arch arm64-v8a] [--out DIR]
#   --symbolic : angr auf Top-Sinks je Lib (schwer, langsam)
#   --arch     : nur eine ABI (default: alle gefundenen)
# ============================================================
set -uo pipefail
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
RE_TRIAGE="$SELF_DIR/re_triage.py"

APK=""; SYMBOLIC=""; ARCH=""; OUT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --symbolic) SYMBOLIC="--symbolic"; shift ;;
        --arch)     ARCH="$2"; shift 2 ;;
        --out)      OUT="$2"; shift 2 ;;
        *)          APK="$1"; shift ;;
    esac
done

[ -n "$APK" ] && [ -f "$APK" ] || { echo "Nutzung: $0 <app.apk> [--symbolic] [--arch <abi>] [--out DIR]"; exit 1; }
command -v unzip >/dev/null || { echo "[FEHLER] unzip fehlt"; exit 1; }
[ -x "$RE_TRIAGE" ] || [ -f "$RE_TRIAGE" ] || { echo "[FEHLER] re_triage.py nicht gefunden: $RE_TRIAGE"; exit 1; }

STAMP="$(date +%F_%H-%M-%S)"
BASE="$(basename "$APK" .apk)"
OUT="${OUT:-/tmp/apk_native_${BASE}_${STAMP}}"
LIBDIR="$OUT/libs"; REPDIR="$OUT/reports"
mkdir -p "$LIBDIR" "$REPDIR"

echo "════════ APK-Native-Triage: $BASE ════════"
# native Libs listen + extrahieren (nur lib/…/*.so)
PAT="lib/*/*.so"; [ -n "$ARCH" ] && PAT="lib/$ARCH/*.so"
mapfile -t SOS < <(unzip -Z1 "$APK" "$PAT" 2>/dev/null)
if [ "${#SOS[@]}" -eq 0 ]; then
    echo "[i] Keine nativen .so gefunden (${ARCH:-alle ABIs}). Reine Java/smali-App → nur jadx/apktool nötig."
    exit 0
fi
echo "[+] ${#SOS[@]} native Lib(s) gefunden."
unzip -o -q "$APK" "$PAT" -d "$LIBDIR" 2>/dev/null

SUMMARY="$OUT/native_triage_summary.md"
{ echo "# APK-Native-Triage: $BASE"; echo; echo "- Zeit: $STAMP · Libs: ${#SOS[@]} · symbolic: ${SYMBOLIC:-nein}"; echo; } > "$SUMMARY"

# Dedup nach Lib-Name über ABIs: dieselbe libfoo.so nur EINMAL triagen (arm64 bevorzugt)
declare -A SEEN
# arm64 zuerst sortieren, damit die bevorzugte ABI gewinnt
mapfile -t SOS_SORTED < <(printf '%s\n' "${SOS[@]}" | sort -r)
for rel in "${SOS_SORTED[@]}"; do
    name="$(basename "$rel")"
    [ -n "${SEEN[$name]:-}" ] && continue
    SEEN[$name]=1
    lib="$LIBDIR/$rel"
    [ -f "$lib" ] || continue
    echo "── $name ──"
    rep="$REPDIR/${name%.so}.md"
    repj="$REPDIR/${name%.so}.json"
    # Fehler EINER Lib darf die Schleife NICHT abbrechen (Script-Baseline: set -uo pipefail, kein -e).
    # Sowohl MD (menschenlesbar) als auch JSON (maschinenlesbar, vom MCP-Collector eingesammelt).
    python3 "$RE_TRIAGE" "$lib" $SYMBOLIC --top 5 --md "$rep" --json "$repj" 2>/dev/null || true
    # Top-Zeile der Sink-Rank-Sektion ziehen; grep/pipefail-Fehler tolerieren
    top="$(grep -A1 'Top verdächtige' "$rep" 2>/dev/null | tail -1 || true)"
    echo "## $name" >> "$SUMMARY"
    echo "- Report: \`$rep\`" >> "$SUMMARY"
    [ -n "$top" ] && echo "- $top" >> "$SUMMARY"
    echo >> "$SUMMARY"
done

echo
echo "[+] Summary → $SUMMARY"
echo "[+] Einzel-Reports → $REPDIR/"
echo "HANDOFF → reverse-engineer: Top-Sink-Libs im Ghidra-Dekompilat vertiefen (45%-Cap)."
