#!/usr/bin/env bash
# Virux M1 benchmark: measures idle/routine CPU and resident memory of viruxd.
# Uses only harmless synthetic telemetry. No privileges required.
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION="${1:-10}"
DB="$(mktemp -d)/bench.db"
BIN=".build/release/viruxd"

echo "== building (release) =="
swift build -c release >/dev/null

echo "== starting viruxd (synth source, ${DURATION}s) =="
"$BIN" --db "$DB" --source synth --seconds "$DURATION" >/dev/null 2>&1 &
PID=$!

sleep 1
SAMPLES=0
SUM_CPU=0
MAX_RSS=0
while kill -0 "$PID" 2>/dev/null; do
  LINE=$(ps -o %cpu=,rss= -p "$PID" 2>/dev/null || true)
  if [ -n "$LINE" ]; then
    CPU=$(echo "$LINE" | awk '{print $1}')
    RSS_KB=$(echo "$LINE" | awk '{print $2}')
    SUM_CPU=$(echo "$SUM_CPU + $CPU" | bc -l)
    SAMPLES=$((SAMPLES+1))
    if [ "$RSS_KB" -gt "$MAX_RSS" ]; then MAX_RSS=$RSS_KB; fi
  fi
  sleep 1
done
wait "$PID" 2>/dev/null || true

echo "== results =="
if [ "$SAMPLES" -gt 0 ]; then
  echo "avg CPU (routine): $(echo "scale=2; $SUM_CPU / $SAMPLES" | bc -l) %"
fi
echo "peak RSS:          $((MAX_RSS/1024)) MB"
echo "db:                $DB"
echo "rows:              $(sqlite3 "$DB" 'select count(*) from events;' 2>/dev/null || echo '?')"