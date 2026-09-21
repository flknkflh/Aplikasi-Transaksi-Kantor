# Local prototype (Docker, persistent)

One `docker compose` stack: **PostgreSQL + the receiver API**. All data lives
in named volumes, so rebuilding the image does **not** wipe accounts,
certificates or signatures.

```sh
cd deploy/local
docker compose up -d --build      # first run also builds the CA
bash seed.sh                      # create admin@local + user@local (once per fresh volume)
```

- Admin console: <http://localhost:8099/admin> — `admin@local` / `admin12345`
- App (Windows / Android): server `http://localhost:8099`, `user@local` / `user12345`
- **Verification-only site**: <http://localhost:8098> — upload a PDF, get a verdict. No login, no signing, no admin. Safe to publish on its own.

### Persistence

| Command | Data |
|---|---|
| `docker compose up -d --build` | **kept** (image rebuilt, volumes reused) |
| `docker compose restart` / `down` then `up` | **kept** |
| `docker compose down -v` | **deleted** — fresh CA + empty database |

Volumes: `pqc-pdf-sign-local_pgdata` (database), `pqc-pdf-sign-local_cadata` (CA keys + ledger).

### Phones on your Wi-Fi

**The QR points at whatever address the signing app is connected to.** So the
only thing to get right is the app's server URL:

- In the Windows / Android app, set the server URL to this machine's LAN IP,
  e.g. `http://192.168.x.x:8099` (not `localhost`).
- Every document that app signs then carries a QR that reads
  `http://192.168.x.x:8099/v/<id>`. Scanning it from any phone on the same
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
