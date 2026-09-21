# Office app stack (Docker)

TTD (login, signing, verification, browser client) + the transaction ledger service behind one origin.
See [ADR-0003](../../docs/adr/0003-office-app.md).

```sh
cd deploy/office
docker compose up -d --build
bash seed.sh
```

| What | URL | Login |
|---|---|---|
| App | http://localhost:18099/app/ | `pemohon@local` / `pemohon12345` (requester), `penyetuju@local` / `penyetuju12345` (approver), `penyetuju2@local` (approver) |
| Admin console (approve accounts) | http://localhost:18099/admin | `admin@local` / `admin12345`, `superadmin` / `superadmin12345` |
| Public verification site | http://localhost:18098 | none |

Roles are assigned by an admin in the app (menu **Peran**, visible to admin accounts).

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
