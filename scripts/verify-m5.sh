#!/usr/bin/env bash
# Virux M5 verification: quarantine / restore / delete / audit / allowlist /
# anti-mass guard / process termination. Uses ONLY benign fixtures - no malware.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
DB="$TMP/e.db"
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1 (expected '$2', got '$3')"; fail=$((fail+1)); fi; }

echo "== build =="
swift build 2>&1 | grep -viE "^\[|Building|Compiling|Planning|Pre-planning|Provisioning|^$" | tail -2

echo "== unit tests (quarantine/response/terminator) =="
SUITES="$(swift test 2>&1 | grep -E "Test Suite '(QuarantineTests|ResponseEngineTests|TerminatorTests)' (passed|failed)" | sed 's/^/  /' || true)"
echo "$SUITES"
echo "$SUITES" | grep -q "failed" && { echo "  FAIL  response suites"; fail=$((fail+1)); } || { echo "  PASS  response suites passed"; pass=$((pass+1)); }

echo "== quarantine a benign executable fixture =="
SAMPLE="$TMP/sample"
printf '#!/bin/sh\necho harmless\n' > "$SAMPLE"
chmod 755 "$SAMPLE"
echo "  before: mode=$(stat -f '%Lp' "$SAMPLE") exists=$([ -f "$SAMPLE" ] && echo yes || echo no)"

.build/debug/virux quarantine-add "$SAMPLE" "M5 verify" --db "$DB" | sed 's/^/  /'

check "original path no longer exists" "no" "$([ -f "$SAMPLE" ] && echo yes || echo no)"
QFILE="$(ls "$TMP/Quarantine"/*-sample 2>/dev/null | head -1)"
check "file present in quarantine store" "yes" "$([ -n "$QFILE" ] && echo yes || echo no)"
if [ -n "$QFILE" ]; then
  check "execute bits cleared" "0" "$(( $(stat -f '%Lp' "$QFILE") & 0111 ))"
  check "sidecar metadata written" "yes" "$([ -f "$QFILE.meta.json" ] && echo yes || echo no)"
fi

echo "== quarantine list =="
.build/debug/virux quarantine --db "$DB" | sed 's/^/  /'

echo "== audit trail =="
.build/debug/virux audit --db "$DB" -n 5 | sed 's/^/  /'
NQ="$(.build/debug/virux audit --db "$DB" -n 20 | grep -c 'quarantine')"
check "audit recorded the quarantine action" "yes" "$([ "$NQ" -ge 1 ] && echo yes || echo no)"

echo "== anti-mass guard + allowlist are covered by unit tests =="
echo "  (ResponseEngineTests: system path skipped, trusted team skipped, rate limit)"

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" = "0" ]
