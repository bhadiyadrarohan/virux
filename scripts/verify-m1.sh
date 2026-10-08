#!/usr/bin/env bash
# Virux M1 verification: builds, tests, and exercises every component end to
# end using only harmless synthetic/replay data. No privileges required.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
TMP="$(mktemp -d)"
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1 (expected '$2', got '$3')"; fail=$((fail+1)); fi
}

echo "== build =="
swift build 2>&1 | grep -viE "^\[|^Building|^Compiling|Planning|Pre-planning|Provisioning|^$" | tail -3

echo "== unit tests =="
swift test 2>&1 | grep -E "Executed [0-9]+ tests" | tail -2 | sed 's/^/  /'

echo "== replay fixture -> store =="
DB="$TMP/events.db"
.build/debug/viruxd --db "$DB" --source "replay:tests/fixtures/sample-eslogger.jsonl" --seconds 2 >/dev/null
ROWS="$(sqlite3 "$DB" 'select count(*) from events;')"
check "rows stored from 6-line fixture" "6" "$ROWS"
EXECS="$(sqlite3 "$DB" "select count(*) from events where kind='exec';")"
check "exec events parsed" "2" "$EXECS"

echo "== CLI =="
.build/debug/virux status --db "$DB" | grep -q "state:" && echo "  PASS  virux status" && pass=$((pass+1)) || { echo "  FAIL  virux status"; fail=$((fail+1)); }
H="$(.build/debug/virux hash tests/fixtures/sample-eslogger.jsonl | awk '{print $1}')"
[ "${#H}" = "64" ] && echo "  PASS  virux hash (64-hex)" && pass=$((pass+1)) || { echo "  FAIL  virux hash"; fail=$((fail+1)); }

echo "== python worker =="
python3 worker/virux_worker.py --selftest | grep -q "SELFTEST PASS" && echo "  PASS  worker selftest" && pass=$((pass+1)) || { echo "  FAIL  worker selftest"; fail=$((fail+1)); }
SOCK="$TMP/worker.sock"
python3 worker/virux_worker.py --socket "$SOCK" >/dev/null 2>&1 &
WPID=$!
sleep 1
ROUND="$(python3 - "$SOCK" <<'PY'
import json, socket, struct, sys
def call(o):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1])
    d=json.dumps(o).encode(); s.sendall(struct.pack(">I",len(d))+d)
    (n,)=struct.unpack(">I", s.recv(4)); b=b""
    while len(b)<n: b+=s.recv(n-len(b))
    s.close(); return json.loads(b)
print(call({"cmd":"ping"})["pong"]["version"])
PY
)"
kill "$WPID" 2>/dev/null || true
check "worker IPC ping" "0.1.0-m1" "$ROUND"

echo "== menu-bar app (headless) =="
VIRUX_UI_SELFTEST_SECONDS=2 VIRUX_DB="$DB" .build/debug/ViruxMenuBar 2>&1 | grep -q "exiting 0" && echo "  PASS  menu-bar launches and exits cleanly" && pass=$((pass+1)) || { echo "  FAIL  menu-bar"; fail=$((fail+1)); }

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" = "0" ]