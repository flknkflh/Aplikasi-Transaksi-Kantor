#!/usr/bin/env bash
# Demo accounts for the integrated office app (idempotent):
#   superadmin / superadmin12345      admin console (/admin) + office roles
#   admin@local / admin12345          admin console
#   pemohon@local / pemohon12345      requester   (Budi Santoso)
#   penyetuju@local / penyetuju12345  approver    (Gita Aurora)
#   penyetuju2@local / penyetuju12345 approver    (Sari Wulandari)
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

curl -sS -X POST "$BASE/api/v1/admin/admins" -H "Authorization: Bearer $SU" -H 'Content-Type: application/json' \
  -d '{"username":"admin@local","password":"admin12345"}' >/dev/null || true
echo ">> admin@local ready"

# email password full_name position nip -> account id (registers + approves; reuses an existing one)
person() {
  local email=$1 pass=$2 name=$3 pos=$4 nip=$5 id
  id=$(curl -sS -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$pass\",\"full_name\":\"$name\",\"display_name\":\"$name\",\"organization\":\"Dinas Contoh\",\"position\":\"$pos\",\"nip\":\"$nip\"}" | jval account_id || true)
  [ -n "$id" ] || id=$(curl -fsS "$BASE/api/v1/admin/accounts" -H "Authorization: Bearer $SU" | tr '}' '\n' | grep "\"$email\"" | jval account_id || true)
  [ -n "$id" ] && curl -fsS -X POST "$BASE/api/v1/admin/accounts/$id/approve" -H "Authorization: Bearer $SU" >/dev/null || true
  echo "$id"
}
P1=$(person pemohon@local pemohon12345 "Budi Santoso, S.Kom." "Staf Pengadaan" "198501012010011001")
P2=$(person penyetuju@local penyetuju12345 "Gita Aurora, S.Ap., M.P.A." "Kepala Bagian Umum" "198704012011012005")
P3=$(person penyetuju2@local penyetuju12345 "Sari Wulandari, S.E." "Kepala Bagian Keuangan" "198203152009012003")
echo ">> pemohon@local, penyetuju@local, penyetuju2@local ready"

role() { curl -fsS -X PUT "$BASE/office/roles/$1" -H "Authorization: Bearer $SU" -H 'Content-Type: application/json' \
  -d "{\"role\":\"$2\",\"email\":\"$3\",\"name\":\"$4\"}" >/dev/null; }
role "$P1" requester pemohon@local "Budi Santoso, S.Kom."
role "$P2" approver penyetuju@local "Gita Aurora, S.Ap., M.P.A."
role "$P3" approver penyetuju2@local "Sari Wulandari, S.E."
echo ">> office roles set"

cat <<EOT

  Aplikasi       : $BASE/app/
     pemohon@local    / pemohon12345     (pemohon — membuat pengajuan)
     penyetuju@local  / penyetuju12345   (penyetuju — menyetujui dengan TTD)
     penyetuju2@local / penyetuju12345   (penyetuju kedua)
  Konsol admin   : $BASE/admin   (admin@local / admin12345  atau  $SU_USER / $SU_PASS)
  Verifikasi     : ${PQC_VERIFY_URL:-http://localhost:18098}
EOT
