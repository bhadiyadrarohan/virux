#!/usr/bin/env bash
# Virux M3 verification: detection engine end to end on a safe scenario fixture.
# Observe-only. No privileges required, no real malware.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1 (expected '$2', got '$3')"; fail=$((fail+1)); fi; }

echo "== build =="
swift build 2>&1 | grep -viE "^\[|Building|Compiling|Planning|Pre-planning|Provisioning|^$" | tail -2

echo "== unit tests =="
swift test 2>&1 | grep -E "Executed [0-9]+ tests" | tail -3 | sed 's/^/  /'

echo "== detection scenario -> store (observe-only) =="
DB="$TMP/det.db"
.build/debug/viruxd --db "$DB" --source "replay:tests/fixtures/detection-scenario.jsonl" --seconds 2 >/dev/null

TOTAL="$(sqlite3 "$DB" "select count(*) from detections;")"
check "detections recorded (deduped)" "4" "$TOTAL"
CRIT="$(sqlite3 "$DB" "select count(*) from detections where severity='critical';")"
check "exactly one critical (mass rename, deduped)" "1" "$CRIT"
MED="$(sqlite3 "$DB" "select count(*) from detections where severity='medium';")"
check "three medium findings" "3" "$MED"

echo "== detections view =="
.build/debug/virux detections --db "$DB" -n 10 | sed 's/^/  /'

echo
echo "== signature verify-before-apply (tamper check) =="
swift test --filter SignatureTests 2>&1 | grep -E "Executed [0-9]+ tests" | tail -1 | sed 's/^/  /'

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" = "0" ]
