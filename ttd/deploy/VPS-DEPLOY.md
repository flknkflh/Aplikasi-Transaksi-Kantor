# Deploy to a VPS (public IP, HTTP)

Prototype deployment on a fresh Ubuntu/Debian VPS. Everything runs in Docker;
data lives in named volumes and survives rebuilds. Plain HTTP on the public IP
(good enough for a prototype; add HTTPS/Caddy later).

Assumes: `PUBLIC_IP=136.244.116.132`, ports **8099** (full API + admin) and
**8098** (verify-only site) open to the internet.

---

## 0. Secure the box (do this first)

```bash
passwd                       # set a new root password — the old one has been shared around
# recommended: add your SSH key and disable password login
```

## 1. Install Docker + git

```bash
apt-get update
apt-get install -y git curl
curl -fsSL https://get.docker.com | sh
docker --version && docker compose version
```

## 2. Open the firewall

```bash
# if ufw is active:
ufw allow OpenSSH
ufw allow 8099/tcp
ufw allow 8098/tcp
ufw --force enable
ufw status
```
(If the VPS panel has its own firewall, allow 22, 8099, 8098 there too.)

## 3. Get the code

```bash
cd /opt
git clone https://github.com/flknkflh/TTD_ELEKTRONIK.git pqc
cd pqc/deploy/local
```

## 4. Configure

```bash
cp .env.example .env
# generate real secrets:
sed -i "s|^PQC_JWT_SECRET=.*|PQC_JWT_SECRET=$(openssl rand -hex 32)|"  .env
sed -i "s|^PQC_DB_PASSWORD=.*|PQC_DB_PASSWORD=$(openssl rand -hex 16)|" .env
# QR + default app address = the public IP:
sed -i "s|^PQC_PUBLIC_BASE_URL=.*|PQC_PUBLIC_BASE_URL=http://136.244.116.132:8099|" .env
cat .env
```

## 5. Start it

```bash
docker compose up -d --build      # first run builds the image + the lab CA (~2-4 min)
docker compose ps
docker compose logs -f api        # Ctrl+C to stop tailing
```

Expect: `receiver API listening on :8099` and `verification-only site listening on :8098`.

## 6. Create the two starter accounts

```bash
apt-get install -y curl >/dev/null
bash /opt/pqc/deploy/local/seed.sh http://localhost:8099
```

Creates:

| Account | Login | Use |
|---|---|---|
| Admin | `admin@local` / `admin12345` | `http://136.244.116.132:8099/admin` |
| User  | `user@local` / `user12345`   | the desktop / Android app (already approved) |

## 7. Check from your laptop / phone

- Admin console : http://136.244.116.132:8099/admin
- Verify site   : http://136.244.116.132:8098
- Health        : `curl http://136.244.116.132:8099/api/v1/public/ca/root.crt` (should return a PEM)

The desktop `.exe` and Android `.apk` in this repo already default their
server URL to `http://136.244.116.132:8099`, so users just log in — no address
to type. Every QR they produce encodes `http://136.244.116.132:8099/v/<id>`,
which opens in any QR scanner.

---

## Day-2

```bash
cd /opt/pqc/deploy/local
git -C /opt/pqc pull && docker compose up -d --build   # update, keep data
docker compose down                                    # stop, keep data
docker compose down -v                                 # WIPE data (fresh CA + empty DB)
docker compose logs --tail=200 api
```

## If you move to a new IP / add a domain

1. `sed -i "s|^PQC_PUBLIC_BASE_URL=.*|PQC_PUBLIC_BASE_URL=http://NEW-HOST:8099|" .env`
2. `docker compose up -d` (no rebuild needed)
3. New QR codes point at the new host. Old signed PDFs keep their old QR — the
   `/v/<id>` page has an "Alamat server" box to correct it, and users can paste
   the ID into the verify site.
4. Rebuild the apps if you want the new default baked in (`apps/windows` →
   `wails build`, `apps/android` → `./gradlew :app:assembleDebug`).

## Notes

- No HTTPS yet. Browser camera QR-scanning in a web page needs HTTPS; the phone
  and desktop apps do not care. For HTTPS, put Caddy in front (`deploy/lab` has
  a Caddy example) or run `caddy reverse-proxy --from yourdomain --to :8099`.
- The lab Root CA is generated inside the `cadata` volume on first boot. Keep
  that volume. `docker compose down -v` regenerates it and invalidates every
  certificate already issued.
