# Archive app stack (Docker)

Several offices send files to one server; the server signs every upload, records it on the ledger and issues a
receipt. TTD (login, /admin, web client) + the ledger service, behind one origin. See
[ADR-0004](../../docs/adr/0004-archive-server-side-signing.md).

```sh
cd deploy/office
docker compose up -d --build
bash seed.sh
```

| What | URL | Login |
|---|---|---|
| Web app (send / archive) | http://localhost:18099/app/ (also https://localhost:18443/app/) | sender: `pengirim.a@local` / `pengirim12345` (Kantor Cabang A), `pengirim.b@local` (B); `baru@local` = approved but no office yet |
| Central admin (archive console) | same page | `admin@local` / `admin12345` (demo bootstrap admin) |
| Super admin (creates/manages admins only) | http://localhost:18099/superadmin/ | auto-created on first start; see [ADR-0005](../../docs/adr/0005-superadmin-login.md) — password printed ONCE in `docker compose logs ttd \| grep "SUPER ADMIN"` |
| Account approval | http://localhost:18099/admin | same admin login |
| Public receipt check | http://localhost:18099/app/#r=<receipt number> or http://localhost:18098 | none |

A sender only sees the upload screen and their own receipt. The admin sees every office's uploads, can verify
signatures / chain / stored file, download files (one-time links) and manage offices and users.
Config: `SERVER_NAME` (shown as "Server tujuan"), `ARCHIVE_MAX_BYTES` (default 20 GiB per file), `KEYSTORE_KEK` (encrypts all
signing keys at rest — change it and keep it safe; losing it loses the keys).

- `ledger-api` is **not** published to the host: only the TTD server (which authenticates users) can reach it.
- Default: Fabric off (`FABRIC_ENABLED=false`): business events are signed and queued in `outbox_event`.
- **With the blockchain** (verified live):
  ```sh
  # 1) Fabric test network + chaincodes (Linux/WSL with Docker; ~3 min, first run pulls images)
  wsl bash network/bootstrap.sh            # from the repo root; or plain `bash` on Linux
  # 2) connect the office stack to it (adds FABRIC_ENABLED=true + the indexer)
  cd deploy/office
  docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build
  ```
  The UI then shows "Tercatat di ledger" and the block number per event. Check the chain independently:
  `network/query-transaction.sh txn_<id>` (run where the Fabric binaries run, e.g. WSL).
  `bash network/teardown.sh` stops the network; go back to queue-only with a plain `docker compose up -d`.
- `docker compose down` keeps data; `down -v` wipes it (then run `seed.sh` again).
- Change every secret (`.env.example`) before exposing this anywhere; `/internal/office/*` is on the public
  port (secret-guarded) — do not route `/internal/` through a public reverse proxy.
- Back up before you need to: [`backup/`](backup/) dumps both databases, the encrypted keystore, MinIO's
  files, the CA and the legacy object store into one encrypted archive, and `backup/verify-restore.sh` proves
  a given backup actually restores (into a throwaway project, never the live stack). See [BACKUP.md](BACKUP.md).
- HTTPS: `https://localhost:18443` (app) / `https://localhost:18444` (verify-only) run alongside the plain
  HTTP ports above — TLS 1.3 with hybrid post-quantum key exchange, self-signed cert generated on first boot
  (browser will warn — expected). Sends `Strict-Transport-Security` only over HTTPS. See [TLS.md](TLS.md) /
  [ADR-0009](../../docs/adr/0009-tls13-hybrid-pqc.md).
