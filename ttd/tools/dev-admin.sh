#!/usr/bin/env bash
# Provision the accounts a hands-on lab needs on a running dev receiver
# (tools/dev-up.sh):
#
#   * ADMIN  admin@local / admin12345  -> the /admin console
#   * USER   user@local  / user12345   -> the browser app (/app/)
#
#   tools/dev-admin.sh [base-url]
#
# In the RB flow a self-registered user starts "pending"; this script registers
# the user and then approves it with the admin, so the browser app can log straight in.
# Both accounts log in with just email + password. The
# receiver keeps accounts in memory — re-run this after every dev-up.sh
# restart. Use 127.0.0.1 here; the phone uses the LAN URL dev-up.sh printed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BASE="${1:-http://127.0.0.1:8099}"; BASE="${BASE%/}"

jval() { sed -n "s/.*\"$1\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }

if ! curl -fsS "$BASE/api/v1/public/ca/root.crt" >/dev/null 2>&1; then
  echo "!! no receiver at $BASE — run 'bash tools/dev-up.sh' first"; exit 1
fi

reg() { # email pass [full_name] [org] -> echoes account_id (self-registration is always a pending user)
  local email=$1 pass=$2 name=${3:-$1} org=${4:-Lab}
  curl -sS -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json'     -d "{\"email\":\"$email\",\"password\":\"$pass\",\"full_name\":\"$name\",\"organization\":\"$org\"}" | jval account_id
}

login() { # email pass -> access_token
  curl -fsS -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" | jval access_token
}

echo ">> provisioning at $BASE"
# Admins can only be created by the super admin (dev-up.sh sets its password).
SU=$(login superadmin dev-superadmin-12345 || true)
[ -n "$SU" ] || { echo "!! super admin login failed (was the receiver started by tools/dev-up.sh?)"; exit 1; }
curl -sS -X POST "$BASE/api/v1/admin/admins" -H "Authorization: Bearer $SU" -H 'Content-Type: application/json'   -d '{"username":"admin@local","password":"admin12345"}' >/dev/null || true
ADM=$(login admin@local admin12345 || true)
[ -n "$ADM" ] || { echo "!! admin login failed"; exit 1; }
echo "   admin@local ready"

UID_=$(reg user@local user12345 "Budi Santoso" "Dinas Kominfo" || true)
if [ -n "$UID_" ]; then
  curl -fsS -X POST "$BASE/api/v1/admin/accounts/$UID_/approve" -H "Authorization: Bearer $ADM" >/dev/null
  echo "   user@local created + approved"
else
  # already exists: find + approve it (idempotent)
  UID_=$(curl -fsS "$BASE/api/v1/admin/accounts" -H "Authorization: Bearer $ADM" \
    | tr '}' '\n' | grep 'user@local' | jval account_id || true)
  [ -n "$UID_" ] && curl -fsS -X POST "$BASE/api/v1/admin/accounts/$UID_/approve" -H "Authorization: Bearer $ADM" >/dev/null || true
  echo "   user@local reused + approved"
fi

IP_HINT="$(command -v powershell >/dev/null 2>&1 && powershell -NoProfile -Command '
  $i=(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric,ifMetric | Select-Object -First 1).InterfaceIndex
  (Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch "^(127|169\.254)\." } | Select-Object -First 1 -ExpandProperty IPAddress)' 2>/dev/null | tr -d "\r")"
[ -n "$IP_HINT" ] || IP_HINT="<LAN-IP-from-dev-up.sh>"

cat <<EOF

  ┌────────────────────────────────────────────────────────────────
  │  ADMIN CONSOLE  ->  http://$IP_HINT:${BASE/admin
  │    email / password : admin@local / admin12345
  │
  │  APP (browser)  ->  /app/  (layar Masuk)
  │    Alamat           : http://$IP_HINT:${BASE/app/
  │    email / password : user@local / user12345

  └────────────────────────────────────────────────────────────────

  Alur: app -> Masuk  (kunci + sertifikat dibuat OTOMATIS, tanpa langkah manual)
        app -> Tanda Tangani Dokumen -> pilih PDF -> hasil ber-QR
  Konsol admin: tab "Akun pengguna" untuk approve / nonaktifkan / hapus.
EOF
