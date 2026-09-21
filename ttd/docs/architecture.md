# Architecture

Source of truth: `Rencana_Pembuatan_PQC_PDF_Sign_V1_Client_Side.md` for the
crypto/trust model; the **RB-1..RB-6** milestones (see `MEMORY` / commit
history) rework the *business flow* for internal office deployment. This file
tracks decisions as they are implemented.

## Shape

```
user       --register {name,instansi,email,pw}-->  receiver   (account: pending)
admin      --approve (1 click)---------------->    receiver   (account: active)
device app --CSR (silent, on first login)---->    receiver --> online CA auto-issues the cert
device app --original PDF + QR placement---->    receiver --> returns PDF with a placed QR stamp
device app --signed PDF--------------------->     receiver --> strict verify -> storage / audit / public verifier
admin      --disable/delete account---------->    receiver --> revoke all its certs + republish CRL
```

The device still holds the only copy of its ML-DSA-65 private key; signing
happens on-device and the server has no signing endpoint (§17.5). The QR stamp is drawn server-side at the spot the signer chose in the app
(so `core` needs no PDF-composition library) and signed on-device with the
rest of the document. Public verification needs no account.

## Modules (this repo)

* **core** (`example.internal/pqc-pdf-sign/core`) — no UI, no framework, no
  ambient network. Pure functions over `[]byte`. Consumed directly by the
  Windows client and, through `core/mobilebridge`, by the Android AAR.
  * `keys` — ML-DSA-65 generate / PKCS#8 marshal / parse / fingerprint / key-pair match.
  * `enrollment` — `CreateDeviceCSR`, `ParseAndValidateCSR` (proof of possession, algo check, subject ignored).
  * `signing` — `SignPDF` (PAdES-B, SHA-512), `BuildSignatureAppearance` (identity, time, serial). No PDF-composition dependency; the RB QR stamp is drawn by the server before signing.
  * `verification` — `VerifyPDF` against an explicit Root CA; offline CRL check; shared JSON result (§11.3).
  * `certutil` — X.509/CRL parsing, profile enforcement, chain build.
  * `labpki` — **lab only** Root/Intermediate/device/CRL generation for fixtures.
  * `spike` — the M1 end-to-end proof, one call, returns a metrics report.
* **apps/windows** — `internal/keystore` (DPAPI-wrapped device key, §12.1),
  `internal/apiclient` (§17 client), `internal/appcore` (the seven §20 pages,
  GUI-independent, tested end-to-end). `cmd/pqcsign-desktop` is the Wails v2
  shell binding `appcore`; `cmd/pqcsign-cli` is the M1 spike. The private key
  is generated in `appcore`, wrapped by `keystore` immediately, and unwrapped
  only for one operation.
* **apps/android** — M5. Consumes `pqcsign.aar` built from `core/mobilebridge` via gomobile.
* **server** — M6. `internal/store`: an `api.Store` interface with a
  concurrency-safe in-memory impl and a `Postgres` impl (embedded
  `schema_migrations`-guarded migrations; the full `api_test.go` suite passes
  against real PG16). `store.NewS3Objects` puts signed blobs in MinIO/S3, else
  an `objects` table. `internal/auth`: Argon2id + HS256 JWT + RFC 6238 TOTP.
  `internal/api`: all §17 core routes; TOTP MFA enforced on enrollment,
  device-loss, and all admin routes (or disabled with `PQC_MFA_NOT_REQUIRED=1`
  on a dev receiver); per-route rate limits. Receiver-only: no endpoint signs a
  PDF. Submit runs `core/verification` strictly + DB checks (cert registered to
  this account+device, active, not revoked, public-id in the PDF matches the
  reservation). RB additions: account lifecycle (`pending`/`active`/`disabled`)
  in `handlers.go`/`accounts.go`, online CA issuance in `devissue.go`
  (`Config.LabIssuer` → `ca-admin` subprocess for issue/revoke/CRL), the
  server-side placed QR stamp in `stamp.go` + `stamppng.go` (uses `pdfcpu` +
  `x/image`, server module only), and the static operator console at `GET /admin` (`adminui.html`).
  `deploy/lab/` runs it as caddy+api+postgres+minio via Compose.
* **tools/ca-admin** — M2 done: offline CLI for CSR validation, operator-
  assigned cert issuance, revocation ledger, ML-DSA-65 CRL publishing; keeps
  Root/Intermediate keys in its own dir, publishes only `public/`. M7 adds
  key encryption / PKCS#11 and signed enrollment-package import/export.

## Frozen interfaces

Keep these stable across UI framework choices (§6):

* Key blob: unencrypted PKCS#8 DER/PEM in memory; OS wrapping is the platform layer's job.
* CSR: PKCS#10 PEM, ML-DSA-65, self-signed (proof of possession).
* Device certificate: X.509, ML-DSA-65, `keyUsage=digitalSignature`,
  EKU `1.3.6.1.5.5.7.3.36` (id-kp-documentSigning), `CA:FALSE`.
* Verification result JSON: see `verification.Result` / §11.3.
* Signature: PAdES-B, CMS pure ML-DSA-65, digest SHA-512, SubFilter `ETSI.CAdES.detached`.

## Open items

* Bind `public_id` into signed PDF `/Info` metadata (today it is in the visible
  appearance and a CMS `Contact` attribute, both inside the signed byte range).
* Offline CRL is checked by `core`, not by `digitorus/pdfsign`'s verifier
  (which has no "supply CRL bytes" input) — revisit if that API gains one.
* TSA / PAdES-B-T is a post-V1 addition (§4 note).
