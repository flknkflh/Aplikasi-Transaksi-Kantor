# Local prototype (Docker, persistent)

One `docker compose` stack: **PostgreSQL + the receiver API**. All data lives
in named volumes, so rebuilding the image does **not** wipe accounts,
certificates or signatures.

```sh
cd ttd/deploy/local
docker compose up -d --build      # first run also builds the browser client + the CA
bash seed.sh                      # create superadmin/admin@local/user@local (once per fresh volume)
```

- **Browser app (TTD)**: <http://localhost:18099/app/> — `user@local` / `user12345`. The first login creates the device key **in the browser** under a PIN you choose (min. 6 characters); the certificate is issued automatically.
- Admin console: <http://localhost:18099/admin> — `admin@local` / `admin12345` (or `superadmin` / `superadmin12345`)
- **Verification-only site**: <http://localhost:18098> — upload a PDF, get a verdict. No login, no signing, no admin. Safe to publish on its own.

Host ports are 18099 / 18098 (override with `PQC_API_PORT` / `PQC_VERIFY_PORT`) so this stack does not collide with a standalone PQC PDF Sign lab on 8099 / 8098. The Compose project is named `ledger-ttd`, so its volumes (`ledger-ttd_pgdata`, `ledger-ttd_cadata`, `ledger-ttd_objdata`) are separate too.

Without Docker: `bash ../../tools/dev-up.sh` (in-memory store, lab CA) then `bash ../../tools/dev-admin.sh`.

> The app opens over plain HTTP on `localhost` (a secure context, so the WebCrypto device-binding layer is active). Reached from another machine over plain `http://<LAN-IP>` the key is still PIN-protected but that extra layer is unavailable and the page says so — put it behind HTTPS for real use.

### Persistence

| Command | Data |
|---|---|
| `docker compose up -d --build` | **kept** (image rebuilt, volumes reused) |
| `docker compose restart` / `down` then `up` | **kept** |
| `docker compose down -v` | **deleted** — fresh CA + empty database |

Volumes: `ledger-ttd_pgdata` (database), `ledger-ttd_cadata` (CA keys + ledger), `ledger-ttd_objdata` (signed PDFs).

### Phones on your Wi-Fi

**The QR points at whatever address the browser used to reach the server.** So the
only thing to get right is the address you open `/app/` on:

- Open the app via this machine's LAN IP, e.g. `http://192.168.x.x:18099/app/` (not `localhost`).
- Every document signed there then carries a QR that reads
  `http://192.168.x.x:18099/v/<id>`. Scanning it from any phone on the same
  Wi-Fi opens the result page directly — no setup on the phone.
- The `/v/<id>` page still has an **"Alamat server"** box if you ever need to
  point it somewhere else (it's remembered).

The verification site also has **"📷 Pindai QR dengan kamera"** for scanning
from a webcam (desktop, or a phone over HTTPS). Plain `http://<LAN-IP>` blocks
browser camera access, so on a phone use the built-in camera app instead — the
QR is a normal link and opens the result directly.

If the app is connected via `localhost` (signer runs on the same box as the
server), a link would be useless from a phone, so the QR falls back to the
bare verification ID as text: scan it, open `http://192.168.x.x:8098`, set
**Alamat server**, and paste the ID into **"masukkan ID verifikasi"**.

You can also force the QR host regardless of the app:

```sh
PQC_PUBLIC_BASE_URL=http://192.168.x.x:8098 docker compose up -d --build
```

### What this configuration does

- No MFA. Rate limiting is off. Single-box prototype.
- The CA runs **inside** the container and issues device certificates
  automatically on first enrolment (no manual step).
- Signed-PDF blobs are stored in the database (`objects` table); no MinIO.
