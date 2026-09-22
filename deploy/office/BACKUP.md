# Backup & restore — the "office" stack

Scripts in [`backup/`](backup/). See [ADR-0006](../../docs/adr/0006-dependency-and-backup-hygiene.md)
for why they work this way.

## What's covered

| Data | How | Included |
|---|---|---|
| `ttd-db` (accounts, sessions, signatures, superadmin security) | `pg_dump --format=custom` | ✅ |
| `ledger-db` (archive items, event chain, outbox) | `pg_dump --format=custom` | ✅ |
| `ledger_keystore` (every sender/system signing key, encrypted under `KEYSTORE_KEK`) | volume tar | ✅ |
| `minio_data` (the uploaded files themselves) | volume tar | ✅ |
| `ttd_ca` (lab CA material, dev/lab issuer only) | volume tar | ✅ |
| `ttd_objects` (legacy TTD-signed PDFs, if that flow was ever used) | volume tar | ✅ |
| `ledger_uploads` (scratch space for in-progress, not-yet-completed uploads) | — | ❌ not needed: a sender just resumes or restarts |
| The Fabric ledger itself | — | ❌ out of scope here — see below |

**The Fabric ledger is not part of this backup.** It is a blockchain: every event is already
replicated across every peer organization's own storage by design. Losing one peer's ledger is
a `network/` recovery concern (rejoin the channel, pull blocks from other peers), not a
data-loss concern the way losing the only copy of a Postgres database would be — see
[ADR-0001](../../docs/adr/0001-fase1-spike-scope.md). `ttd-db`/`ledger-db` remain the systems of
record for everything a human needs to read (who sent what, receipts, status); Fabric is the
tamper-evidence layer on top of them.

## RPO / RTO (targets for this stack; adjust to your own risk tolerance)

- **RPO (how much you could lose):** as often as `backup.sh` runs. Not scheduled by default —
  add it to cron/Task Scheduler yourself (example below). Daily is the minimum sane cadence
  once real offices depend on this.
- **RTO (how long a restore takes):** for the demo-sized dataset used to write these scripts,
  a full `restore.sh` run (both databases + all four volumes + bringing the stack back up)
  took under two minutes. It scales roughly with `minio_data` size — budget accordingly once
  real files are involved (`ARCHIVE_MAX_BYTES` allows up to 20 GiB per file by default).

## Encryption & access

The bundle is encrypted with `openssl enc -aes-256-cbc -pbkdf2` under `BACKUP_ENCRYPTION_KEY`
before it ever touches disk — the dumps contain password hashes, sender IPs, file names and
descriptions, none of which should sit around in plaintext. Generate the key once
(`openssl rand -hex 32`), store it **somewhere other than next to the backups** (a password
manager, a secrets store — not this repo, not the same disk as `deploy/office/backups/`), and
losing it means the backups are unrecoverable, same as losing `KEYSTORE_KEK` means losing the
signing keys. Restrict who can read the backup files and who holds the key separately if more
than one person operates this.

## Running it

```sh
cd deploy/office/backup

# one-time: generate and SAVE somewhere safe (not in this repo)
openssl rand -hex 32

# back up (needs the stack running: docker compose up -d)
BACKUP_ENCRYPTION_KEY=<key> bash backup.sh
#   -> ../backups/office-backup-<timestamp>.tar.enc

# prove it actually restores — into a THROWAWAY project on ports 18199/18198,
# never the live stack; tears itself down when done, pass or fail
BACKUP_ENCRYPTION_KEY=<key> bash verify-restore.sh

# real disaster recovery: overwrite the live "office" stack itself
BACKUP_ENCRYPTION_KEY=<key> bash restore.sh ../backups/office-backup-<timestamp>.tar.enc --live
```

`verify-restore.sh` is the actual "does this backup work" test: it restores into an isolated
compose project, checks the app answers on its port, checks both databases have the expected
rows, and checks `ledger-api` booted without a keystore error — then deletes everything it
created. Run it after every `backup.sh` (or at least regularly) — a backup nobody has restored
is not a backup, it's an unverified file.

**Schedule both, don't just write them once.** Example crontab entry (adjust paths/key
handling — do not hardcode the key in a world-readable crontab; read it from a root-only file
or your secrets manager instead):

```
0 2 * * *  cd /path/to/deploy/office/backup && BACKUP_ENCRYPTION_KEY="$(cat /root/.backup-key)" bash backup.sh >> /var/log/office-backup.log 2>&1
0 4 * * 0  cd /path/to/deploy/office/backup && BACKUP_ENCRYPTION_KEY="$(cat /root/.backup-key)" bash verify-restore.sh >> /var/log/office-restore-drill.log 2>&1
```

## Retention

Not automated here — decide a policy (e.g. daily for 14 days, weekly for 3 months) and prune
`deploy/office/backups/` (or wherever you move completed backups off-host to) accordingly. Off-host
storage is on you too: a backup that lives on the same disk/host as the stack it backs up
doesn't survive that host failing.
