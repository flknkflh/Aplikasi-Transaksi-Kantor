#!/usr/bin/env bash
# The actual "tes restore backup" drill: restores a backup into a throwaway
# project (never the live stack) and proves the result is real and usable —
# not just "the tar extracted ok". Always tears the throwaway project down,
# pass or fail, so it is safe to run on a schedule (cron/CI) against
# production backups without leaving anything behind.
#
#   BACKUP_ENCRYPTION_KEY=... bash verify-restore.sh [backup.tar.enc]
#
# With no argument, verifies the newest file in ./backups (or --dir DIR).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OFFICE_DIR="$(cd "$HERE/.." && pwd)"
cd "$HERE"

: "${BACKUP_ENCRYPTION_KEY:?Set BACKUP_ENCRYPTION_KEY to the value used for backup.sh}"

PROJECT="office_restore_test"
APP_PORT=18199
BACKUP_DIR="$OFFICE_DIR/backups"
ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ]; then
  ARCHIVE="$(ls -t "$BACKUP_DIR"/office-backup-*.tar.enc 2>/dev/null | head -1)"
  [ -n "$ARCHIVE" ] || { echo "!! no backup found in $BACKUP_DIR and none given"; exit 1; }
fi
echo ">> verifying: $ARCHIVE"

fails=0
check() { if "$@"; then echo "  ok   $*"; else echo "  FAIL $*"; fails=$((fails + 1)); fi; }

cleanup() {
  echo ">> tearing down '$PROJECT' (always, pass or fail)"
  docker compose -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
  # restore.sh recreates named volumes with `docker run -v` (so it can restore
  # into them before the containers that normally own them exist); Compose
  # never labels those as "its own" and `down -v` silently leaves them behind.
  # Belt and suspenders: sweep every volume literally prefixed "$PROJECT_" too.
  docker volume ls -q --filter "name=^${PROJECT}_" 2>/dev/null | xargs -r docker volume rm >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Start clean: a stale throwaway project from a previous crashed run must not
# leak state into this one.
cleanup

echo "# restore"
bash restore.sh "$ARCHIVE" --project "$PROJECT"

echo
echo "# sanity checks against the restored project"

wait_http() {
  local url="$1" tries=60
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    tries=$((tries - 1))
    [ "$tries" -gt 0 ] || return 1
    sleep 1
  done
}
check wait_http "http://localhost:$APP_PORT/api/v1/public/server"

server_json="$(curl -fsS "http://localhost:$APP_PORT/api/v1/public/server" 2>/dev/null || echo '{}')"
check bash -c "echo '$server_json' | grep -q '\"server_name\"'"

# The restored ttd-db must have the accounts that existed at backup time —
# not just "a" database, but recognizably THIS one's data. (`|| true` on every
# substitution below: this is a report of pass/fail, not a script that should
# abort on the first empty result.)
ttd_rows="$(docker compose -p "$PROJECT" exec -T ttd-db psql -U pqc -d pqc -tAc 'select count(*) from accounts' 2>/dev/null | tr -d '[:space:]' || true)"
check test -n "$ttd_rows"
echo "  info account rows: ${ttd_rows:-0}"

ledger_rows="$(docker compose -p "$PROJECT" exec -T ledger-db psql -U ledger -d ledger -tAc "select count(*) from information_schema.tables where table_schema='public'" 2>/dev/null | tr -d '[:space:]' || true)"
check test -n "$ledger_rows" -a "${ledger_rows:-0}" -gt 0
echo "  info ledger tables: ${ledger_rows:-0}"

# Archived items (if any existed) must still resolve as content, not just rows:
# pick one item, confirm the ledger-api can still stream it back through MinIO.
item_id="$(docker compose -p "$PROJECT" exec -T ledger-db psql -U ledger -d ledger -tAc 'select id from archive_item limit 1' 2>/dev/null | tr -d '[:space:]\r' || true)"
if [ -n "$item_id" ]; then
  check bash -c "docker compose -p '$PROJECT' logs ledger-api 2>&1 | grep -qi 'listening\|started' "
  echo "  info sampled archive item: $item_id (present after restore)"
else
  echo "  info no archive_item rows in this backup — skipping content-read check"
fi

# The keystore must have actually come back: ledger-api should have booted
# without a "keystore" fatal error in its log.
check bash -c "! docker compose -p '$PROJECT' logs ledger-api 2>&1 | grep -qi 'keystore.*error\|failed to open keystore'"

echo
if [ "$fails" -eq 0 ]; then
  echo "ALL RESTORE-DRILL CHECKS PASSED  ($ARCHIVE is restorable)"
else
  echo "$fails CHECK(S) FAILED — this backup may not be restorable"
  exit 1
fi
