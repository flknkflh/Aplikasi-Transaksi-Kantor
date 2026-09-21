#!/usr/bin/env bash
# Demo data for the archive app (idempotent):
#   superadmin / superadmin12345     central admin (archive console + /admin)
#   admin@local / admin12345         central admin
#   office "Kantor Cabang A":  pengirim.a@local / pengirim12345
#   office "Kantor Cabang B":  pengirim.b@local / pengirim12345
#   baru@local / pengirim12345       approved but NOT assigned to an office yet
#
#   deploy/office/seed.sh [base-url]
set -euo pipefail
BASE="${1:-http://localhost:18099}"; BASE="${BASE%/}"
SU_USER="${PQC_SUPERADMIN_USERNAME:-superadmin}"
SU_PASS="${PQC_SUPERADMIN_PASSWORD:-superadmin12345}"
jval() { sed -n "s/.*\"$1\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }

for i in $(seq 1 60); do curl -fsS "$BASE/api/v1/public/ca/root.crt" >/dev/null 2>&1 && break; sleep 2; done
curl -fsS "$BASE/api/v1/public/ca/root.crt" >/dev/null || { echo "!! no server at $BASE — run 'docker compose up -d --build' first"; exit 1; }

login() { curl -fsS -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"$2\"}" | jval access_token; }
SU=$(login "$SU_USER" "$SU_PASS") || { echo "!! super-admin login failed"; exit 1; }
echo ">> $SU_USER ready"
AUTH=(-H "Authorization: Bearer $SU" -H 'Content-Type: application/json')

curl -sS -X POST "$BASE/api/v1/admin/admins" "${AUTH[@]}" -d '{"username":"admin@local","password":"admin12345"}' >/dev/null || true
echo ">> admin@local ready"

# offices (create returns the slug id; a duplicate answers 409, then the id is the slug of the name)
office() { # name -> id
  local out; out=$(curl -sS -X POST "$BASE/office/archive/offices" "${AUTH[@]}" -d "{\"name\":\"$1\"}")
  local id; id=$(echo "$out" | jval id)
  [ -n "$id" ] || id=$(echo "$1" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]\+/-/g; s/^-//; s/-$//')
  echo "$id"
}
OA=$(office "Kantor Cabang A"); OB=$(office "Kantor Cabang B")
echo ">> offices: $OA, $OB"

# email name -> account id (registers + approves; reuses an existing account)
person() {
  local email=$1 name=$2 id
  id=$(curl -sS -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"pengirim12345\",\"full_name\":\"$name\",\"display_name\":\"$name\",\"organization\":\"Demo\"}" | jval account_id || true)
  [ -n "$id" ] || id=$(curl -fsS "$BASE/api/v1/admin/accounts" -H "Authorization: Bearer $SU" | tr '}' '\n' | grep "\"$email\"" | jval account_id || true)
  [ -n "$id" ] && curl -fsS -X POST "$BASE/api/v1/admin/accounts/$id/approve" -H "Authorization: Bearer $SU" >/dev/null || true
  echo "$id"
}
assign() { curl -fsS -X PUT "$BASE/office/archive/members/$1" "${AUTH[@]}" -d "{\"organization_id\":\"$2\",\"email\":\"$3\",\"name\":\"$4\"}" >/dev/null; }

PA=$(person pengirim.a@local "Dina Pratiwi")
PB=$(person pengirim.b@local "Eko Wijaya")
person baru@local "Fajar Baru" >/dev/null
assign "$PA" "$OA" pengirim.a@local "Dina Pratiwi"
assign "$PB" "$OB" pengirim.b@local "Eko Wijaya"
echo ">> senders ready and assigned"

cat <<EOT

  Aplikasi web   : $BASE/app/
     pengirim.a@local / pengirim12345   (Kantor Cabang A — hanya bisa mengirim)
     pengirim.b@local / pengirim12345   (Kantor Cabang B)
     baru@local       / pengirim12345   (disetujui, BELUM ditetapkan ke kantor)
  Admin pusat    : login di $BASE/app/ dengan  admin@local / admin12345  atau  $SU_USER / $SU_PASS
                   (lihat semua kiriman, verifikasi, unduh, atur kantor & pengguna)
  Konsol akun    : $BASE/admin   (setujui akun baru)
  Cek bukti      : ${PQC_VERIFY_URL:-http://localhost:18098}   atau tab "Cek bukti" di aplikasi
EOT
