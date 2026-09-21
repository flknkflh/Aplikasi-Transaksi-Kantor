#!/usr/bin/env bash
# Bring up a local lab: lab CA + receiver API on the LAN, so a phone or a
# second machine can talk to it (no Docker). Ctrl+C to stop.
#
#   tools/dev-up.sh [port]
#
# Then open the browser app:  http://<this-machine-IP>:<port>/app/  (Step 4 of the TTD plan)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PORT="${1:-8099}"
DEVDIR="$ROOT/dist/dev"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; *) EXE="" ;; esac
mkdir -p "$DEVDIR"

echo ">> build"
( cd tools/ca-admin && go build -o "$DEVDIR/ca-admin$EXE" . )
( cd server && go build -o "$DEVDIR/pqc-api$EXE" ./cmd/api )

if [ ! -f "$DEVDIR/ca/public/root-ca.crt.pem" ]; then
  echo ">> lab CA (dist/dev/ca)"
  "$DEVDIR/ca-admin$EXE" init --dir "$DEVDIR/ca" >/dev/null
fi

# best-effort LAN IP: the address of whichever interface carries the default
# route (skips VMware/VirtualBox/VPN adapters).
IP="$(
  {
    command -v powershell >/dev/null 2>&1 && powershell -NoProfile -Command '
      $i = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric,ifMetric | Select-Object -First 1).InterfaceIndex
      (Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch "^(127|169\.254)\." } |
        Select-Object -First 1 -ExpandProperty IPAddress)' 2>/dev/null
  } ||
  { hostname -I 2>/dev/null | tr ' ' '\n' | grep -Ev '^(127|169\.254)\.' | head -1; } ||
  echo "127.0.0.1"
)"
IP="$(echo "$IP" | tr -d '\r' | head -1)"
[ -n "$IP" ] || IP="127.0.0.1"
echo ">> LAN IP: $IP   (if wrong, run 'ipconfig' and use your Wi-Fi IPv4)"

cat <<EOF

  ┌─────────────────────────────────────────────────────────────
  │  Receiver API listening on 0.0.0.0:$PORT  (in-memory store)
  │
  │  Phone / other machine on the same Wi-Fi:
  │    Server URL   ->  http://$IP:$PORT
  │
  │  Admin console   :  http://$IP:$PORT/admin      (approve + issue in a browser)
  │  Public verifier :  http://$IP:$PORT/api/v1/verify
  │  Root CA         :  $DEVDIR/ca/public/root-ca.crt.pem
  │  CA operator CLI :  $DEVDIR/ca-admin$EXE  (issue certs offline)
  │
  │  In ANOTHER shell, create the admin login:
  │    bash tools/dev-admin.sh http://127.0.0.1:$PORT
  │  then open the admin console and sign in.
  │  (full scripted flow: tests/e2e/local-run.sh)
  │
  │  Ctrl+C to stop.
  └─────────────────────────────────────────────────────────────

EOF

exec env PQC_JWT_SECRET="dev-secret-0123456789" PQC_RATE_LIMIT_DISABLED=1 \
  PQC_DEV_LAB_CA_ADMIN="$DEVDIR/ca-admin$EXE" \
  PQC_DEV_LAB_CA_DIR="$DEVDIR/ca" \
  "$DEVDIR/pqc-api$EXE" --addr "0.0.0.0:$PORT" \
  --root-ca "$DEVDIR/ca/public/root-ca.crt.pem" \
  --ca-chain "$DEVDIR/ca/public/ca-chain.pem" \
  --public-base-url "http://$IP:$PORT"
