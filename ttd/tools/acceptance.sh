#!/usr/bin/env bash
# Run the full V1 acceptance suite (Rencana V1 §25). Maps to docs/acceptance-v1.md.
#   tools/acceptance.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

pass=0 fail=0
run() {
  printf '\n\033[1m>> %s\033[0m\n' "$1"; shift
  if "$@"; then echo "   PASS"; pass=$((pass+1)); else echo "   FAIL"; fail=$((fail+1)); fi
}

run "core — unit + fuzz-seed + golden"          bash -c 'cd core && go test ./...'
run "server — api + auth + acceptance (§25.4-6)" bash -c 'cd server && go test ./...'
run "tools/ca-admin — M2 + M7 gate"             bash -c 'cd tools/ca-admin && go test ./...'
run "fuzz smoke — stdlib parsers (10s each)"    bash -c '
  cd core
  go test ./keys/       -run=x -fuzz="^FuzzParsePKCS8$"           -fuzztime=10s &&
  go test ./enrollment/ -run=x -fuzz="^FuzzParseAndValidateCSR$" -fuzztime=10s &&
  go test ./certutil/   -run=x -fuzz="^FuzzValidateCRL$"         -fuzztime=10s'

printf '\n\033[1m=== acceptance: %d passed, %d failed ===\033[0m\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
echo "See docs/acceptance-v1.md for the §25 matrix and the manual-sign-off items."
