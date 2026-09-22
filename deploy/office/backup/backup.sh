#!/usr/bin/env bash
# Back up the "office" stack's data: both Postgres databases (logical dump,
# not a raw data-dir copy, so it restores across Postgres patch versions),
# the KEYSTORE_KEK-encrypted signing keystore, MinIO's stored files, the lab
# CA, and the legacy TTD object store. The whole bundle is then symmetrically
# encrypted — the dumps contain password hashes, sender IPs and file
# metadata, so it must never sit on disk in plaintext.
#
#   BACKUP_ENCRYPTION_KEY=$(openssl rand -hex 32) bash backup.sh [output-dir]
#
# Requires: the "office" stack running (docker compose up -d), openssl.
# See ../BACKUP.md and docs/adr/0006-dependency-and-backup-hygiene.md.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OFFICE_DIR="$(cd "$HERE/.." && pwd)"
cd "$OFFICE_DIR"

: "${BACKUP_ENCRYPTION_KEY:?Set BACKUP_ENCRYPTION_KEY (e.g. \$(openssl rand -hex 32)) — backups contain password hashes, sender IPs and file metadata and must not be written in plaintext. Store this key somewhere OTHER than next to the backups.}"

OUT_ROOT="${1:-$OFFICE_DIR/backups}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/office-backup-$TS"
mkdir -p "$STAGE"
# Docker Desktop's CLI wants a native Windows path for a bind-mount SOURCE on
# Windows; plain `pwd` (POSIX-style) fails silently as an empty/wrong mount.
# `pwd -W` only exists in Git Bash/MSYS — elsewhere STAGE is already fine as-is.
STAGE_HOST="$STAGE"; ( cd "$STAGE" && pwd -W ) >/dev/null 2>&1 && STAGE_HOST="$(cd "$STAGE" && pwd -W)"

running() { docker compose ps --status running --services 2>/dev/null | grep -qx "$1"; }
for svc in ttd-db ledger-db minio; do
  running "$svc" || { echo "!! $svc is not running (docker compose up -d first)"; exit 1; }
done

echo ">> postgres: ttd-db"
docker compose exec -T ttd-db pg_dump -U pqc --format=custom pqc > "$STAGE/ttd-db.dump"

echo ">> postgres: ledger-db"
docker compose exec -T ledger-db pg_dump -U ledger --format=custom ledger > "$STAGE/ledger-db.dump"

tar_volume() {
  local vol="$1" file="$2"
  if ! docker volume inspect "office_${vol}" >/dev/null 2>&1; then
    echo "   (skip: volume office_${vol} does not exist)"
    return
  fi
  echo ">> volume: $vol"
  MSYS_NO_PATHCONV=1 docker run --rm -v "office_${vol}:/data:ro" -v "$STAGE_HOST:/backup" alpine:3.20 \
    tar czf "/backup/$file" -C /data .
}
tar_volume ledger_keystore keystore.tar.gz     # signing private keys (encrypted at rest under KEYSTORE_KEK)
tar_volume minio_data      minio-data.tar.gz   # uploaded files — usually the biggest part of the backup
tar_volume ttd_ca          ttd-ca.tar.gz       # lab CA material (dev/lab issuer only)
tar_volume ttd_objects     ttd-objects.tar.gz  # legacy TTD-signed PDFs, if that flow was ever used
# NOT backed up: ledger_uploads — scratch space for in-progress uploads only;
# an interrupted upload just gets resumed or restarted, there is nothing durable there.

echo ">> checksums"
( cd "$STAGE" && sha256sum -- * > SHA256SUMS )

cat > "$STAGE/MANIFEST.txt" <<EOF
office archive app backup
created (UTC): $TS
repo commit:   $(git -C "$OFFICE_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
contents:      ttd-db.dump ledger-db.dump keystore.tar.gz minio-data.tar.gz ttd-ca.tar.gz ttd-objects.tar.gz
NOT included:  ledger_uploads (transient scratch — see backup.sh)
NOT included:  the Fabric ledger itself — it is replicated across peer organizations by design;
               recovering a peer is a network/ concern, not a data-loss concern (docs/adr/0001).
restore:       BACKUP_ENCRYPTION_KEY=... bash restore.sh <this file>
verify:        BACKUP_ENCRYPTION_KEY=... bash verify-restore.sh <this file>   (automated restore drill)
EOF

echo ">> encrypting"
mkdir -p "$OUT_ROOT"
OUT="$OUT_ROOT/office-backup-$TS.tar.enc"
tar cz -C "$WORK" "office-backup-$TS" | \
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_ENCRYPTION_KEY -out "$OUT"

echo
echo "  Backup:  $OUT"
echo "  Size:    $(du -h "$OUT" | cut -f1)"
echo "  Restore: BACKUP_ENCRYPTION_KEY=... bash restore.sh \"$OUT\""
echo "  Verify:  BACKUP_ENCRYPTION_KEY=... bash verify-restore.sh \"$OUT\""
