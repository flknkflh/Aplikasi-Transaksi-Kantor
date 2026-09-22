#!/usr/bin/env bash
# Restore a backup.sh archive. Verifies checksums before touching anything.
#
# By default restores into a SEPARATE, throwaway compose project
# ("office_restore_test") on alternate ports (18199/18198) so nothing live is
# ever touched — this is what verify-restore.sh uses for the automated drill.
# Pass --live to actually overwrite the running "office" stack's data (real
# disaster recovery; stops the app containers, restores, restarts them).
#
#   BACKUP_ENCRYPTION_KEY=... bash restore.sh <backup.tar.enc> [--live] [--project NAME]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OFFICE_DIR="$(cd "$HERE/.." && pwd)"
cd "$OFFICE_DIR"

: "${BACKUP_ENCRYPTION_KEY:?Set BACKUP_ENCRYPTION_KEY to the same value used for backup.sh}"

ARCHIVE="${1:?usage: restore.sh <backup.tar.enc> [--live] [--project NAME]}"
shift || true
PROJECT="office_restore_test"
APP_PORT=18199
VERIFY_PORT=18198
TLS_APP_PORT=18543
TLS_VERIFY_PORT=18544
LIVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --live) LIVE=1; PROJECT="office" ;;
    --project) PROJECT="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$LIVE" = 1 ]; then
  echo "!! --live: this OVERWRITES the '$PROJECT' stack's data (ttd-db, ledger-db, keystore, MinIO, CA)."
  echo "   Ctrl+C within 10s to abort."
  sleep 10
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo ">> decrypting"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_ENCRYPTION_KEY -in "$ARCHIVE" | tar xz -C "$WORK"
STAGE="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)"
[ -n "$STAGE" ] && [ -f "$STAGE/SHA256SUMS" ] || { echo "!! archive did not extract as expected"; exit 1; }
STAGE_HOST="$STAGE"; ( cd "$STAGE" && pwd -W ) >/dev/null 2>&1 && STAGE_HOST="$(cd "$STAGE" && pwd -W)"

echo ">> verifying checksums"
( cd "$STAGE" && sha256sum -c SHA256SUMS )
cat "$STAGE/MANIFEST.txt"

wait_pg() {
  local svc="$1" user="$2" tries=60
  until docker compose -p "$PROJECT" exec -T "$svc" pg_isready -U "$user" >/dev/null 2>&1; do
    tries=$((tries - 1))
    [ "$tries" -gt 0 ] || { echo "!! $svc never became ready"; exit 1; }
    sleep 1
  done
}

echo ">> stopping app containers (only the databases run during restore)"
docker compose -p "$PROJECT" up -d ttd-db ledger-db
docker compose -p "$PROJECT" stop ttd ledger-api indexer minio >/dev/null 2>&1 || true
wait_pg ttd-db pqc
wait_pg ledger-db ledger

echo ">> restoring ttd-db"
docker compose -p "$PROJECT" exec -T ttd-db pg_restore -U pqc -d pqc --clean --if-exists --no-owner --no-privileges < "$STAGE/ttd-db.dump" || true

echo ">> restoring ledger-db"
docker compose -p "$PROJECT" exec -T ledger-db pg_restore -U ledger -d ledger --clean --if-exists --no-owner --no-privileges < "$STAGE/ledger-db.dump" || true

restore_volume() {
  local vol="$1" file="$STAGE/$2"
  [ -f "$file" ] || { echo "   (skip: $2 not in this backup)"; return; }
  echo ">> volume: $vol"
  MSYS_NO_PATHCONV=1 docker run --rm -v "${PROJECT}_${vol}:/data" -v "$STAGE_HOST:/backup:ro" alpine:3.20 sh -c \
    "rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null; tar xzf /backup/$2 -C /data"
}
restore_volume ledger_keystore keystore.tar.gz
restore_volume minio_data      minio-data.tar.gz
restore_volume ttd_ca          ttd-ca.tar.gz
restore_volume ttd_objects     ttd-objects.tar.gz
restore_volume ttd_tls         ttd-tls.tar.gz

echo ">> starting the full stack"
if [ "$LIVE" = 1 ]; then
  docker compose -p "$PROJECT" up -d
else
  PQC_APP_PORT="$APP_PORT" PQC_VERIFY_PORT="$VERIFY_PORT" \
    PQC_TLS_APP_PORT="$TLS_APP_PORT" PQC_TLS_VERIFY_PORT="$TLS_VERIFY_PORT" \
    docker compose -p "$PROJECT" up -d
fi

echo
echo "  Restored into project '$PROJECT'."
if [ "$LIVE" = 0 ]; then
  echo "  App:    http://localhost:$APP_PORT/app/  (HTTPS: https://localhost:$TLS_APP_PORT/app/)"
  echo "  Verify: http://localhost:$VERIFY_PORT"
  echo "  Tear down when done:  docker compose -p $PROJECT down -v"
fi
