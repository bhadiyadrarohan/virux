#!/usr/bin/env bash
# M7 verification: ransomware behaviour coverage + external-drive on-connect checks.
# Everything runs against benign fixtures inside a temp directory. No user data
# is touched and no malware is used.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=.build/debug/virux
pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
# contains LABEL HAYSTACK PATTERN   (literal match)
contains(){ if grep -qF -- "$3" <<<"$2"; then ok "$1"; else bad "$1 (missing '$3')"; fi; }

echo "M7 verification (ransomware + external drives)"

if swift build >/dev/null 2>&1; then ok "build"; else bad "build"; exit 1; fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
DB="$TMP/events.db"
WATCH="$TMP/watch"; mkdir -p "$WATCH"

# --- canary lifecycle -------------------------------------------------------
out=$($BIN canary plant "$WATCH" --db "$DB" 2>&1)
check "canary plant creates 3 canaries" "$(grep -cF planted <<<"$out")" "3"

$BIN canary check --db "$DB" >/dev/null 2>&1
check "canary check exits 0 when intact" "$?" "0"

printf 'attacker overwrote this\n' > "$WATCH/DO_NOT_DELETE_virux_canary.dat"
out=$($BIN canary check --db "$DB" 2>&1); rc=$?
check "canary check exits 2 when tampered" "$rc" "2"
contains "canary check reports CHANGED" "$out" "CHANGED"

rm -f "$WATCH/~\$virux_canary.docx"
out=$($BIN canary check --db "$DB" 2>&1)
contains "canary check reports MISSING" "$out" "MISSING"

# --- volume enumeration -----------------------------------------------------
out=$($BIN volumes 2>&1)
contains "volumes enumerates a mounted volume" "$out" "free "
contains "volumes enumerates the boot volume" "$out" "[internal]"

# --- on-connect scan of a prepared removable-style directory ----------------
ON="$TMP/usb"; mkdir -p "$ON"
printf 'x' > "$ON/autorun.inf"
printf 'x' > "$ON/setup.command"
printf 'x' > "$ON/.hidden_payload_thing"   # hidden, but not executable -> not flagged
chmod +x "$ON/.hidden_payload_thing"        # now it is
out=$($BIN volumes "$ON" 2>&1)
contains "on-connect scan flags autorun.inf" "$out" "autorun"
contains "on-connect scan flags a root payload" "$out" "executable-payload"
contains "on-connect scan flags a hidden executable" "$out" "hidden-executable"
check "on-connect scan reports entry budget" "$(grep -cF 'entries in' <<<"$out")" "1"

# --- safe ransomware simulation --------------------------------------------
out=$($BIN sim-ransomware --db "$DB" 2>&1)
contains "simulation fires R-005 (mass rename)" "$out" "R-005"
contains "simulation fires R-007 (canary)" "$out" "R-007"
contains "simulation fires R-008 (mass modify)" "$out" "R-008"
contains "simulation contains the canary" "$out" "canary quarantined ->"
contains "simulation states benign-fixture scope" "$out" "benign fixtures only"

# --- impact view ------------------------------------------------------------
out=$($BIN impact --db "$DB" 2>&1)
contains "impact summary printed" "$out" "potentially affected files:"
contains "impact groups by extension" "$out" "by extension:"

# --- live daemon path: canary fires from real telemetry shape ---------------
LIVE="$TMP/live"; mkdir -p "$LIVE/watch"
LDB="$LIVE/events.db"
$BIN canary plant "$LIVE/watch" --db "$LDB" >/dev/null 2>&1
LCAN="$LIVE/watch/DO_NOT_DELETE_virux_canary.dat"
printf '{"event_type": "rename", "time": "2026-10-08T10:00:00.000000Z", "process": {"audit_token": {"pid": 4242, "ppid": 1}, "executable": {"path": "/tmp/locker"}}, "event": {"rename": {"source": {"path": "%s"}, "destination": {"path": "%s"}}}}\n' "$LCAN" "$LCAN" > "$LIVE/replay.jsonl"
.build/debug/viruxd --db "$LDB" --source "replay:$LIVE/replay.jsonl" --seconds 3 >/dev/null 2>&1
out=$($BIN detections --db "$LDB" 2>&1)
contains "daemon fires R-007 on live telemetry" "$out" "Canary (decoy) file touched"
contains "canary detection is critical/high" "$out" "[critical/high]"

# --- module tests -----------------------------------------------------------
if swift test --filter ViruxCoverageTests >/dev/null 2>&1; then
  ok "ViruxCoverageTests pass"
else
  bad "ViruxCoverageTests pass"
fi

echo
echo "M7: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
