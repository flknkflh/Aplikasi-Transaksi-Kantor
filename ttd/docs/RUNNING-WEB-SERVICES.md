# Web Service yang Berjalan di Server Ini

Dokumen ini menjelaskan **layanan web yang sedang aktif** di VPS (`/opt/pqc`),
cara mengaksesnya (termasuk lewat SSH), serta daftar lengkap endpoint-nya.

Diambil dari kondisi runtime pada 2026-09-09. Sumber kebenaran kode:
[server/internal/api/api.go](server/internal/api/api.go),
[server/cmd/api/main.go](server/cmd/api/main.go),
[deploy/local/docker-compose.yml](deploy/local/docker-compose.yml),
[deploy/local/entrypoint.sh](deploy/local/entrypoint.sh).

---

## 1. Ringkasan

Proyek **PQC PDF Sign V1** — penandatanganan PDF pasca-kuantum (ML-DSA-65 /
FIPS 204), penandatanganan dilakukan **sepenuhnya di sisi klien**. Server hanya
menerima PDF yang **sudah** ditandatangani, memverifikasinya secara ketat
terhadap Root CA, menyimpannya, dan menyediakan verifier publik. **Tidak ada
endpoint yang menandatangani PDF atas nama pengguna.**

Semua layanan dijalankan lewat Docker Compose stack `pqc-pdf-sign` di
[deploy/local/](deploy/local/).

### Container yang berjalan

| Container | Image | Status | Port (host) |
|---|---|---|---|
| `pqc-pdf-sign-api-1` | `pqc-pdf-sign-api` (build lokal) | Up | `8098->8098`, `8099->8099` |
| `pqc-pdf-sign-postgres-1` | `postgres:17-alpine` | Up (healthy) | hanya internal (`5432`, tidak diekspos) |

Konfigurasi runtime container API (`docker inspect`):

```
PQC_DATABASE_URL   = postgres://pqc:***@postgres:5432/pqc?sslmode=disable
PQC_JWT_SECRET     = *** (32 byte hex)
PQC_PUBLIC_BASE_URL= http://136.244.116.132:8099
```

Perintah start di dalam container ([entrypoint.sh](deploy/local/entrypoint.sh)):

```sh
api --addr ":8099" --verify-addr ":8098" --public-base-url "$PQC_PUBLIC_BASE_URL"
```

Karakteristik konfigurasi lokal ini:

- **Tanpa MFA/TOTP**, **rate limiting dimatikan** (`PQC_RATE_LIMIT_DISABLED=1`).
- **CA berjalan di dalam container** dan menerbitkan sertifikat perangkat
  **otomatis** saat enrolment pertama (tidak ada langkah manual).
- Blob PDF yang sudah ditandatangani disimpan di **database** (tabel `objects`),
  **tanpa MinIO**.
- Data persisten di named volume: `..._pgdata` (database) dan `..._cadata`
  (kunci CA + ledger). `docker compose down -v` menghapusnya.

---

## 2. Dua HTTP service

Satu binary `api` membuka **dua listener terpisah**:

### 2a. Port 8099 — Receiver API + Admin Console (lengkap)

Alamat: `http://<host>:8099`
Handler: `Server.Routes()` di [api.go:158](server/internal/api/api.go#L158)

Berisi **semua** rute: auth, device enrollment, reservasi & submit tanda tangan,
download, verifier publik, endpoint CA publik, seluruh rute admin, dan konsol
operator statis di `/admin`.

- Admin console: `http://<host>:8099/admin`
- Kredensial seed (dari [seed.sh](deploy/local/seed.sh), jika sudah dijalankan):
  - admin: `admin@local` / `admin12345`
  - user : `user@local` / `user12345`

### 2b. Port 8098 — Situs Verifikasi Publik (read-only)

Alamat: `http://<host>:8098`
Handler: `Server.VerifyRoutes()` di
[verifyservice.go:10](server/internal/api/verifyservice.go#L10)

Hanya subset publik: halaman upload PDF + verdict, resolusi target QR
(`/s/{id}` → `/v/{id}`), PDF otoritatif di balik QR, record publik, dan
material CA. **Tanpa login, tanpa signing, tanpa admin.** CORS `*` (halaman
boleh dibuka di satu alamat sambil menunjuk server di alamat lain melalui kotak
"Alamat server"). Aman dipublikasikan berdiri sendiri.

Judul halaman: `Verifikasi Dokumen — PQC PDF Sign`, berbahasa Indonesia, ada
tombol "📷 Pindai QR dengan kamera".

---

## 3. Cara mengakses lewat SSH

Port `8098`/`8099` di-bind ke `0.0.0.0`, jadi ada dua opsi.

### Opsi A — SSH port forwarding (paling andal)

Dari terminal **komputer lokal** (bukan di dalam sesi SSH), buka koneksi baru:

```sh
ssh -L 8099:localhost:8099 -L 8098:localhost:8098 <user>@136.244.116.132
```

Biarkan sesi terbuka, lalu di browser lokal:

- `http://localhost:8099/admin` — API + Admin UI
- `http://localhost:8098/` — situs verifikasi

Menambahkan tunnel ke sesi SSH yang sudah berjalan: tekan `~C` lalu ketik
`-L 8099:localhost:8099`.

### Opsi B — Akses langsung lewat IP publik

```
http://136.244.116.132:8099/admin
http://136.244.116.132:8098/
```

Hanya berhasil jika firewall (Vultr Cloud Firewall / `ufw`) mengizinkan port
8098–8099. Cek: `sudo ufw status`.

### Cek cepat dari dalam server

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8099/admin              # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8099/api/v1/public/ca/root.crt  # 200
curl -s http://127.0.0.1:8098/ | head                                            # halaman verifikasi
docker compose -f /opt/pqc/deploy/local/docker-compose.yml ps
docker logs --tail 50 pqc-pdf-sign-api-1
```

---

## 4. Daftar endpoint lengkap (port 8099)

Prefix semua endpoint JSON: `/api/v1`. Auth memakai header
`Authorization: Bearer <access_token>` (JWT, TTL 15 menit). Peran: `user` dan
`admin`.

### 4.1 Auth & akun

| Metode & Path | Auth | Keterangan |
|---|---|---|
| `POST /api/v1/auth/register` | — | `{email,password,full_name,organization}` + opsional `{display_name,position,nip,issued_place,role}`. Membuat akun **pending**. |
| `POST /api/v1/auth/login` | — | `{email,password,code?}`. Ditolak `403 {account_status:"pending"}` sampai admin approve. `code` wajib bila MFA aktif. |

> Catatan: [docs/api.md](docs/api.md) juga mencantumkan `auth/mfa/setup`,
> `auth/mfa/verify`, `auth/refresh`, `auth/logout` sebagai bagian dari desain;
> pada build yang berjalan hanya `register` + `login` yang ter-mount di
> [api.go](server/internal/api/api.go#L161). MFA & rate limit dimatikan pada
> konfigurasi lokal ini.

### 4.2 Perangkat (device) & enrolment

| Metode & Path | Auth | Keterangan |
|---|---|---|
| `POST /api/v1/devices` | user | Daftarkan perangkat baru (`{label,platform}`). |
| `GET /api/v1/devices` | user | Daftar perangkat milik akun. |
| `POST /api/v1/devices/{device_id}/csr` | user | Kirim CSR PEM. Setelah akun approved, CA online **auto-issue** sertifikat (`status:"issued"`, `certificate_serial`). |
| `GET /api/v1/devices/{device_id}/certificate` | user | Ambil sertifikat perangkat (PEM). |
| `POST /api/v1/devices/{device_id}/report-lost` | user | Laporkan perangkat hilang → memicu revocation. |

### 4.3 Tanda tangan (alur reserve → sign di klien → submit)

| Metode & Path | Auth | Keterangan |
|---|---|---|
| `POST /api/v1/signatures/reserve` | user | Pesan `public_id` untuk dokumen yang akan ditandatangani. |
| `POST /api/v1/signatures/{public_id}/stamp` | user | Gambar stempel QR yang ditempatkan (query `x,y,w`), kembalikan PDF. |
| `PUT /api/v1/signatures/{public_id}/document` | user | Unggah PDF yang **sudah** ditandatangani. Server verifikasi ketat (§15.3) sebelum menyimpan. |
| `GET /api/v1/signatures/{public_id}` | user | Metadata satu tanda tangan. |
| `GET /api/v1/signatures/{public_id}/download` | user | Unduh PDF tersimpan. |
| `GET /api/v1/me/signatures` | user | Semua tanda tangan milik akun. |

### 4.4 Verifikasi & material publik (tanpa auth)

| Metode & Path | Keterangan |
|---|---|
| `POST /api/v1/verify` | Unggah PDF (multipart), kembalikan verdict JSON. Publik. |
| `GET /api/v1/public/signatures/{public_id}` | Record publik satu tanda tangan. |
| `GET /s/{public_id}` | Target QR: konfirmasi alamat server lalu redirect ke `/v/{id}`. |
| `GET /v/{public_id}` | Halaman hasil verifikasi (HTML, untuk manusia). |
| `GET /v/{public_id}/document` | PDF otoritatif di balik QR. |
| `GET /api/v1/public/ca/root.crt` | Root CA (PEM). |
| `GET /api/v1/public/ca/chain.pem` | Root + Intermediate (PEM). |
| `GET /api/v1/public/ca/crl.pem` | CRL terkini (PEM). |

### 4.5 Admin (peran `admin`)

| Metode & Path | Keterangan |
|---|---|
| `GET /api/v1/admin/capabilities` | Feature-detect (`{lab_issuer:bool}`). |
| `GET /api/v1/admin/accounts` | Daftar akun. |
| `POST /api/v1/admin/accounts/{id}/approve` | Setujui akun pending. |
| `POST /api/v1/admin/accounts/{id}/disable` | Nonaktifkan akun (revoke semua sertifikatnya + republish CRL). |
| `POST /api/v1/admin/accounts/{id}/enable` | Aktifkan kembali. |
| `PATCH /api/v1/admin/accounts/{id}` | Ubah `{full_name,organization}`. |
| `DELETE /api/v1/admin/accounts/{id}` | Hapus (cascade revoke + CRL; tombstone bila ada histori). |
| `GET /api/v1/admin/enrollments` | Daftar permintaan enrolment. |
| `GET /api/v1/admin/enrollments/{id}/export` | Ekspor data enrolment. |
| `POST /api/v1/admin/enrollments/{id}/approve` | Setujui enrolment. |
| `POST /api/v1/admin/enrollments/{id}/certificate` | Terbitkan sertifikat (cek chain + kecocokan kunci CSR). |
| `POST /api/v1/admin/enrollments/{id}/issue-lab` | **DEV-only**, hanya bila `LabIssuer` diset — jalankan CA online lewat `ca-admin`. Aktif pada konfigurasi lokal ini. |
| `POST /api/v1/admin/certificates/{id}/revoke` | Cabut sertifikat (dengan reason code). |
| `POST /api/v1/admin/crl/import` | Impor / ganti CRL. |
| `GET /api/v1/admin/audit-events` | Log audit (`?limit=`). |
| `GET /admin`, `GET /admin/` | Konsol operator statis (HTML+JS). |

---

## 5. Endpoint pada situs verifikasi (port 8098)

Subset publik dari daftar di atas:

```
GET  /                                     halaman upload + verdict + pemindai QR
POST /api/v1/verify                        verifikasi PDF (multipart)
GET  /s/{public_id}                        resolver target QR
GET  /v/{public_id}                        halaman hasil (manusia)
GET  /v/{public_id}/document               PDF otoritatif
GET  /api/v1/public/signatures/{public_id} record publik
GET  /api/v1/public/ca/root.crt            Root CA (PEM)
GET  /api/v1/public/ca/chain.pem           chain (PEM)
GET  /api/v1/public/ca/crl.pem             CRL (PEM)
```

Semua respons `Cache-Control: no-store`, CORS `Access-Control-Allow-Origin: *`,
metode `GET, POST, OPTIONS`.

---

## 6. Profil kripto (§4)

- Tanda tangan: **ML-DSA-65**, CMS pure mode (RFC 9882)
- Digest: **SHA-512**
- PDF: **PAdES Baseline-B** (`PAdES_B`)
- Trust: **hanya Root CA eksplisit** — root yang tertanam di PDF tidak pernah
  dijadikan anchor (§5.3)
- Timestamp: **tidak ada** di V1 (waktu klaim klien ditampilkan tapi tidak
  dipercaya)

## 7. Invariant keamanan (§5.3)

- Tidak ada private key di source, log, DB, HTTP request, telemetry, crash
  report, atau gambar.
- Server **tidak punya** endpoint yang menandatangani PDF atas nama pengguna.
- Satu kunci per perangkat; tidak pernah disalin antar perangkat.
- Semua keputusan trust memakai Root CA yang dikonfigurasi, bukan root di
  dalam PDF.
- Identitas sertifikat berasal dari akun terverifikasi, bukan dari subject CSR.

---

## 8. Operasi umum

```sh
cd /opt/pqc/deploy/local

docker compose ps                       # status
docker compose logs -f api              # ikuti log API
docker compose up -d --build            # rebuild image, data tetap
docker compose restart api              # restart hanya API
docker compose down                     # stop, data tetap
docker compose down -v                  # stop + HAPUS data (CA & DB baru)
bash seed.sh                            # buat admin@local + user@local (sekali per volume baru)
bash seed.sh http://localhost:8099      # seed ke base URL tertentu
```

Konfigurasi ada di [deploy/local/.env](deploy/local/.env) — yang penting
`PQC_PUBLIC_BASE_URL` (dituju oleh QR code, sekaligus alamat server default
untuk aplikasi). Di VPS set ke IP/domain publik dan pertahankan port `:8099`
(atau `:8098` bila QR ingin diarahkan ke situs verifikasi).

---

## 9. Deploy alternatif (tidak berjalan sekarang)

| Path | Isi |
|---|---|
| [deploy/lab/](deploy/lab/) | Varian "lab": **Caddy** (TLS, port `8443`) + API + Postgres + **MinIO** (blob storage). Hanya Caddy yang terekspos; postgres & minio di jaringan internal. Butuh `.env.lab` + CA yang dibuat manual lewat `ca-admin init`. |
| [deploy/production/](deploy/production/) | Resep produksi (PKI ceremony air-gapped, lihat [docs/pki-ceremony.md](docs/pki-ceremony.md)). |

---

## 10. Listener lain di server (bukan bagian aplikasi)

`ss -tlnp` juga menampilkan:

| Port | Proses | Keterangan |
|---|---|---|
| `22` | `sshd` | akses SSH |
| `127.0.0.1:35993`, `127.0.0.1:42447`, `127.0.0.1:40979` | `code-*` | VS Code Remote / server ekstensi |
| `127.0.0.1:13921`, `127.0.0.1:62613` | `MainThread` | proses pendukung ekstensi editor |
| `127.0.0.53:53` | `systemd-resolve` | DNS stub lokal |

Semuanya lokal (`127.0.0.1`) kecuali SSH; tidak terkait PQC PDF Sign.
