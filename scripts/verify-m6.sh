#!/usr/bin/env bash
# Virux M6 verification: searchable history, incident reports, process trees,
# persistence scan, and the dashboard shell. Safe fixtures only.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
DB="$TMP/m6.db"
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1 (expected '$2', got '$3')"; fail=$((fail+1)); fi; }

echo "== build =="
swift build 2>&1 | grep -viE "^\[|Building|Compiling|Planning|Pre-planning|Provisioning|^$" | tail -2

echo "== unit tests (forensics) =="
SUITES="$(swift test 2>&1 | grep -E "Test Suite '(SearchTests|ProcessTreeTests|ReportTests|GraphTests|PersistenceTests)' (passed|failed)" | sed 's/^/  /' || true)"
echo "$SUITES"
echo "$SUITES" | grep -q failed && { echo "  FAIL forensics suites"; fail=$((fail+1)); } || { echo "  PASS  forensics suites"; pass=$((pass+1)); }

echo "== seed store from the detection scenario =="
.build/debug/viruxd --db "$DB" --source "replay:tests/fixtures/detection-scenario.jsonl" --seconds 3 >/dev/null

echo "== searchable history =="
OUT="$(.build/debug/virux find --db "$DB" --path LaunchDaemons -n 5)"
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q "com.evil.plist" && { echo "  PASS  find --path"; pass=$((pass+1)); } || { echo "  FAIL  find --path"; fail=$((fail+1)); }
K="$(.build/debug/virux find --db "$DB" --kind open -n 20 | grep -c '^\[')"
[ "$K" -ge 1 ] && { echo "  PASS  find --kind open ($K)"; pass=$((pass+1)); } || { echo "  FAIL  find --kind"; fail=$((fail+1)); }

echo "== incident report =="
REP="$(.build/debug/virux report --db "$DB" 3)"
echo "$REP" | head -12 | sed 's/^/  /'
for needle in "Incident report" "Why it was flagged" "Process chain" "Evidence" "Recommended next actions"; do
  echo "$REP" | grep -q "$needle" && { echo "  PASS  report contains '$needle'"; pass=$((pass+1)); } || { echo "  FAIL  report missing '$needle'"; fail=$((fail+1)); }
done

echo "== process tree =="
TREE="$(.build/debug/virux tree --db "$DB" --since 48h)"
echo "$TREE" | head -8 | sed 's/^/  /'
echo "$TREE" | grep -q "pid" && { echo "  PASS  process tree rendered"; pass=$((pass+1)); } || { echo "  FAIL  process tree"; fail=$((fail+1)); }
ANC="$(.build/debug/virux tree --db "$DB" --since 48h --pid 200)"
echo "$ANC" | sed 's/^/  /'
echo "$ANC" | grep -q "pid 100" && { echo "  PASS  ancestry resolved"; pass=$((pass+1)); } || { echo "  FAIL  ancestry"; fail=$((fail+1)); }

echo "== persistence scan =="
PERS="$(.build/debug/virux persistence)"
echo "$PERS" | head -6 | sed 's/^/  /'
echo "$PERS" | grep -q "autostart entries" && { echo "  PASS  persistence scan ran"; pass=$((pass+1)); } || { echo "  FAIL  persistence scan"; fail=$((fail+1)); }

echo "== dashboard shell (headless) =="
UI="$(VIRUX_UI_SELFTEST_SECONDS=3 VIRUX_DB="$DB" .build/debug/ViruxMenuBar 2>&1)"
echo "$UI" | sed 's/^/  /'
echo "$UI" | grep -q "logoLoaded=true" && { echo "  PASS  dashboard launches with the V icon"; pass=$((pass+1)); } || { echo "  FAIL  dashboard"; fail=$((fail+1)); }

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" = "0" ]
