#!/usr/bin/env bash
# Seed the running local stack:
#   superadmin / superadmin12345   -> /admin console, manages admins
#   admin@local / admin12345       -> /admin console (created by the super admin)
#   user@local  / user12345        -> the browser app (/app/) (already approved)
# Idempotent. Data is persistent, so you normally run this once per fresh volume.
#
#   deploy/local/seed.sh [base-url]
set -euo pipefail
BASE="${1:-http://localhost:8099}"; BASE="${BASE%/}"
SU_USER="${PQC_SUPERADMIN_USERNAME:-superadmin}"
SU_PASS="${PQC_SUPERADMIN_PASSWORD:-superadmin12345}"
jval() { sed -n "s/.*\"$1\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }

curl -fsS "$BASE/api/v1/public/ca/root.crt" >/dev/null || { echo "!! no API at $BASE — run 'docker compose up -d' first"; exit 1; }

# The super admin is bootstrapped by the server on first boot (from
# PQC_SUPERADMIN_USERNAME/PASSWORD). Log in as it.
SU=$(curl -fsS -X POST "$BASE/api/v1/auth/login" -d "{\"email\":\"$SU_USER\",\"password\":\"$SU_PASS\"}" | jval access_token || true)
[ -n "$SU" ] || { echo "!! super-admin login failed — check PQC_SUPERADMIN_PASSWORD (server logs the generated one on first boot)"; exit 1; }
echo ">> $SU_USER ready"

# One demo admin, created by the super admin (admins can no longer self-register).
curl -sS -X POST "$BASE/api/v1/admin/admins" -H "Authorization: Bearer $SU" -H 'Content-Type: application/json' \
  -d '{"username":"admin@local","password":"admin12345"}' >/dev/null || true
echo ">> admin@local ready"

# One end user for the app; self-registers pending, the super admin approves.
UID_=$(curl -sS -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d '{"email":"user@local","password":"user12345","role":"user","full_name":"Gita Aurora, S.Ap., M.P.A.","organization":"Deputi Bidang Koordinasi Aparatur","display_name":"Gita Aurora","position":"Plt. Asisten Deputi Perumusan dan Koordinasi Kebijakan Penerapan Akuntabilitas Aparatur dan Pengawasan","nip":"198704012011012005"}' | jval account_id || true)
[ -n "$UID_" ] || UID_=$(curl -fsS "$BASE/api/v1/admin/accounts" -H "Authorization: Bearer $SU" | tr '}' '\n' | grep 'user@local' | jval account_id || true)
[ -n "$UID_" ] && curl -fsS -X POST "$BASE/api/v1/admin/accounts/$UID_/approve" -H "Authorization: Bearer $SU" >/dev/null && echo ">> user@local approved"

cat <<EOF

  Admin console : $BASE/admin        ($SU_USER / $SU_PASS  — super admin)
                  $BASE/admin        (admin@local / admin12345)
  App login     : $BASE              (user@local / user12345)
EOF
