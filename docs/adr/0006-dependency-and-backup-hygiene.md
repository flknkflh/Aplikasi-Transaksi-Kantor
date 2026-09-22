# ADR-0006: Dependency vulnerability scanning + backup/restore drills

**Status:** Accepted (2026-09-22). Closes two gaps from the pre-launch security checklist
review: "update dependency" and "test restore backup".

## Context

A source-level security review (checklist-driven, see the conversation this ADR documents)
found two process gaps that no amount of code review fixes by itself: nothing told anyone when
a dependency got a new CVE, and there was no backup of the stack's data — let alone proof a
backup could be restored. Both are the kind of gap that stays invisible until the day it
matters.

## Decision — dependency scanning

1. **`govulncheck` in CI** (`.github/workflows/dependency-audit.yml`), one job per Go module in
   the workspace (`/go.work` lists all nine: `crypto`, `api`, `audit-service`, `indexer`,
   `chaincode/asset`, `chaincode/transaction`, `ttd/core`, `ttd/server`,
   `ttd/tools/ca-admin`). It runs `GOWORK=off govulncheck ./...` **inside each module
   directory** rather than once at the workspace root — govulncheck needs a `go.mod` to run
   against and workspace-root scanning isn't supported the same way; per-module scanning also
   gives a precise pass/fail per component instead of one opaque result. Triggers: push/PR to
   `main` touching any `go.mod`/`go.sum`/`*.go`, **and** a Monday cron — a dependency can grow
   a new CVE without a single line of this repo changing, so time-based re-scanning matters as
   much as change-triggered scanning.
2. **Dependabot** (`.github/dependabot.yml`): weekly, one entry per Go module (`gomod`), one for
   the e2e test's npm deps, one `docker` entry per Dockerfile plus `deploy/office` (its
   `docker-compose.yml`/`.fabric.yml` pin Postgres/MinIO/Alpine image tags), and one for the
   workflow files themselves (`github-actions`). Dependabot is the "surface it as a PR"
   half — govulncheck in CI is what actually blocks a merge on a real, reachable
   vulnerability; Dependabot alone doesn't know if a flagged version is even reachable code.
3. **Fixed, not just monitored, at the time of writing:** `golang.org/x/crypto` was on v0.55.0
   in four modules (`api`, `ttd/core`, `ttd/server`, `ttd/tools/ca-admin`), which carried two
   SSH-package DoS advisories and one "openpgp is unmaintained" advisory (GO-2026-6355,
   GO-2026-6354, GO-2026-5932) — none reachable from this project's code (none of it uses
   `x/crypto/ssh` or `/openpgp`), but bumping to v0.57.0 costs nothing and removes the noise
   from every future scan. All four modules rebuilt and their existing test suites re-run green
   after the bump.

## Decision — backup & restore

1. **Scope:** `deploy/office/backup/backup.sh` covers both Postgres databases (`ttd-db` via
   logical `pg_dump`, not a raw data-directory copy, so a restore isn't pinned to one Postgres
   patch version; `ledger-db` the same), the `KEYSTORE_KEK`-encrypted signing keystore, MinIO's
   stored files, the lab CA material, and the legacy TTD object store. Deliberately **not**
   included: `ledger_uploads` (scratch space for uploads still in progress — nothing durable to
   lose) and the Fabric ledger itself, which is already replicated across peer organizations by
   the nature of a permissioned blockchain (ADR-0001) — recovering a peer is a `network/`
   concern, not a single-point-of-failure data-loss concern the way a lone Postgres instance is.
2. **Encrypted at rest, always.** The dumps contain password hashes, sender IPs, file names and
   descriptions — real, sensitive data — so `backup.sh` symmetrically encrypts the whole bundle
   (`openssl enc -aes-256-cbc -pbkdf2`, 200k iterations) under `BACKUP_ENCRYPTION_KEY` before it
   ever touches disk; there is no code path that writes an unencrypted bundle to the output
   directory. `restore.sh` verifies a `SHA256SUMS` manifest before touching anything, so a
   corrupted or tampered backup is refused up front rather than partially applied.
3. **The restore is tested by running it, not asserted in a doc.**
   `deploy/office/backup/verify-restore.sh` is the actual "test restore backup" item: it
   restores a given backup into a **throwaway compose project** (`office_restore_test`, on
   alternate ports so it can never collide with a live stack), waits for the app to answer,
   checks both databases have the expected row/table counts, checks `ledger-api` booted without
   a keystore error, and then **always** tears the throwaway project down — containers, and,
   explicitly, its volumes too (Compose's own `down -v` does not remove volumes that were
   populated via a plain `docker run -v` before Compose ever created them, which is how the
   restore has to work — the script sweeps `${PROJECT}_*` volumes directly rather than trust
   `down -v` alone). Run end-to-end against the live demo stack while writing this ADR: a fresh
   backup, a full restore drill, and a torn-down throwaway project with zero leftover containers
   or volumes, confirmed both before and after.
4. **`restore.sh --live` is the disaster-recovery path**, separate from the drill: it stops the
   app containers (keeps only the databases running for `pg_restore`), restores every volume,
   and brings the stack back up in place, with a 10-second abort window and an explicit `--live`
   flag required — the default with no flag is always the safe, throwaway-project restore.
5. **Not automated here: scheduling and retention.** `backup.sh` and `verify-restore.sh` are
   scripts, not a cron job or a systemd timer — BACKUP.md documents an example crontab entry,
   but actually wiring it up (and deciding a retention window, and moving completed backups
   off-host) is an operational decision for whoever runs this in production, not something a
   docker-compose demo stack should silently start doing on its own.

## Consequences — read these

- Chaincode modules (`chaincode/asset`, `chaincode/transaction`) build from a committed
  `vendor/` directory (needed for the Fabric chaincode builder, see `network/bootstrap.sh`'s
  `GOWORK=off` note); `govulncheck` works against them unmodified, confirmed by running it
  locally, so no special-casing was needed in the workflow.
- Dependabot will open PRs weekly; nothing merges them automatically. The govulncheck workflow
  is what actually gates `main` on the `crypto`/ssh/openpgp class of "does this matter" — a
  flagged-but-unreachable vulnerability (there is always at least one somewhere in a large
  dependency graph) does not fail the build, only a **reachable** one does.
- `verify-restore.sh` currently checks structural health (row counts, boot success) rather than
  full content-equality of every archived file against its recorded hash; the archive app
  already has that stronger check built in (`archive_verify.go`'s deep verification), and a
  restored stack can be pointed at it manually for a full audit — wiring that into the
  automated drill is a reasonable next step once real archived files exist to exercise it
  against (the demo stack used to write this ADR had none).
- `BACKUP_ENCRYPTION_KEY` becomes a secret with the same weight as `KEYSTORE_KEK`: losing it
  makes every backup taken under it permanently unreadable. Documented in BACKUP.md, not solved
  automatically — key management here is deliberately the operator's responsibility, the same
  stance already taken for `KEYSTORE_KEK` (ADR-0004).

## Verification

`govulncheck` run locally against all nine modules before and after the `x/crypto` bump (0
reachable vulnerabilities in every module, both before and after; the three named advisories
gone after the bump). `go build ./...` and each module's existing test suite re-run and green
post-bump (`api`, `ttd/core`, `ttd/server`, `ttd/tools/ca-admin`, `crypto`). The backup/restore
scripts run for real against the live `deploy/office` demo stack: `backup.sh` produced a
non-empty encrypted archive with all six components present and checksummed;
`verify-restore.sh` restored it into an isolated project, passed every sanity check (5 account
rows, 20 ledger tables, no keystore error), and left zero containers or volumes behind —
confirmed with `docker ps`/`docker volume ls` immediately after.
