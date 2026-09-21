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
- Fabric is off (`FABRIC_ENABLED=false`): business events are signed and queued in `outbox_event`.
  To drain them onto a chain, run the Fabric test network (`network/bootstrap.sh`), give `ledger-api` the
  `FABRIC_*` variables from `infra/docker-compose.yml`, and set `FABRIC_ENABLED=true`. Not verified live.
- `docker compose down` keeps data; `down -v` wipes it (then run `seed.sh` again).
- Change every secret (`.env.example`) before exposing this anywhere; `/internal/office/*` is on the public
  port (secret-guarded) — do not route `/internal/` through a public reverse proxy.
