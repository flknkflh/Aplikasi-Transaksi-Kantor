# Receiver API (M6)

Endpoint list from Rencana V1 §17. **M6 slice 1 is implemented** in
`server/internal/api` on an in-memory store (`✔` below); the rest lands in
slice 2 (PostgreSQL/MinIO/Docker, MFA/TOTP, refresh-token revocation, rate
limiting).

Implemented (`server/internal/api`, tested in `api_test.go`):

```
✔ POST /api/v1/auth/register          (pending end user only; role in body ignored)
✔ POST /api/v1/auth/login             ({email,password,code?}; code required once MFA is confirmed)
✔ POST /api/v1/auth/mfa/setup         (returns TOTP secret + otpauth:// URL)
✔ POST /api/v1/auth/mfa/verify        ({code} -> confirms the secret)
✔ POST /api/v1/devices
✔ GET  /api/v1/devices
✔ POST /api/v1/devices/{device_id}/csr
✔ GET  /api/v1/devices/{device_id}/certificate
✔ POST /api/v1/devices/{device_id}/report-lost
✔ POST /api/v1/signatures/reserve
✔ PUT  /api/v1/signatures/{public_id}/document      (strict verify, §15.3)
✔ GET  /api/v1/signatures/{public_id}
✔ GET  /api/v1/signatures/{public_id}/download
✔ GET  /api/v1/me/signatures
✔ POST /api/v1/verify                               (public, multipart)
✔ GET  /api/v1/public/signatures/{public_id}
✔ GET  /api/v1/public/ca/root.crt | chain.pem | crl.pem
✔ POST /api/v1/signatures/{public_id}/stamp         (RB-2c: draw a placed QR stamp, returns PDF)
✔ GET  /v/{public_id}/document                      (public: the authoritative signed PDF behind the QR)
✔ GET  /api/v1/admin/enrollments
✔ POST /api/v1/admin/enrollments/{id}/certificate   (chain + CSR-key match check)
✔ POST /api/v1/admin/enrollments/{id}/issue-lab     (RB-1: drive the online CA; when Config.LabIssuer set)
✔ POST /api/v1/admin/certificates/{id}/revoke
✔ POST /api/v1/admin/crl/import
✔ GET  /api/v1/admin/audit-events
✔ GET  /api/v1/admin/capabilities                   ({lab_issuer:bool, role})
✔ GET    /api/v1/admin/admins                        (super admin only: admin roster — admins only, no client accounts)
✔ POST   /api/v1/admin/admins                        (super admin only: {username,password} -> active admin)
✔ PATCH  /api/v1/admin/admins/{id}                   (super admin only: {password} reset and/or {status:"active"|"disabled"})
✔ DELETE /api/v1/admin/admins/{id}                   (super admin only: delete an admin)
✔ GET  /api/v1/admin/accounts                       (RB-1; client + admin rows — mutations below are client-only)
✔ POST /api/v1/admin/accounts/{id}/approve|disable|enable   (CLIENT accounts only — 403 for any admin/superadmin target)
✔ PATCH  /api/v1/admin/accounts/{id}                ({full_name,organization}; client only)
✔ DELETE /api/v1/admin/accounts/{id}                (cascade revoke + CRL; tombstone if it has history; client only)
✔ GET  /admin                                       (static operator console)
```

Slice 2 remainder: `auth/refresh`, `auth/logout`.

## RB business flow (from RB-1..RB-6)

`register` takes `{email,password,full_name,organization}` plus the optional
`{display_name,position,nip}` (empty string when absent; `position`/`nip` are
the signer's fixed identity drawn in the e-signature caption on stamps — the
per-signature "Dikeluarkan di <kota>" is passed to `/stamp` instead, not here)
and always creates a **pending end user** (`role:"user"`). Any `role` in the
body is ignored — admins can no longer self-register. Login is refused (`403
{account_status:"pending"}`) until an admin `POST /admin/accounts/{id}/approve`.

**Account management.** One **super admin** is bootstrapped on first boot from
`PQC_SUPERADMIN_USERNAME` (default `superadmin`) + `PQC_SUPERADMIN_PASSWORD`
(empty → a random password is generated and logged once). Only the super admin
can `POST /api/v1/admin/admins {username,password}` to create an **active**
admin, and only the super admin can `disable`/`enable` an admin account. The
super admin itself cannot be disabled or deleted. A super-admin session
satisfies every `admin/*` route. Once approved, the first
`POST /devices/{id}/csr` from that account is **auto-issued** by the server's
online CA (`Config.LabIssuer`) — the response carries `status:"issued"` and
`certificate_serial`, no separate admin step. Disabling or deleting an account
revokes every certificate it holds and republishes the CRL. Verification stays
public and needs no account.

**MFA gate (§24)**: `POST /devices/{id}/csr`, `POST /devices/{id}/report-lost`,
and every `admin/*` route require a session that presented a valid TOTP code
at login (`mfa` claim). Others are reachable without MFA.

**Rate limits (§24, per minute)**: `auth/login` 10/IP, `signatures/reserve`
60/account, `signatures/{id}/document` 30/account, `verify` 30/IP. Over the
cap → `429` + `Retry-After`. Configurable via `api.Config.RateLimits`.

## Auth
```
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/mfa/setup
POST /api/v1/auth/mfa/verify
```

## Devices and enrollment
```
POST /api/v1/devices
GET  /api/v1/devices
GET  /api/v1/devices/{device_id}
POST /api/v1/devices/{device_id}/csr
GET  /api/v1/devices/{device_id}/certificate
POST /api/v1/devices/{device_id}/report-lost
```

## Signatures
```
POST   /api/v1/uploads                              (resumable upload: -> {upload_id})
PATCH  /api/v1/uploads/{id}?offset=<N>              (append a chunk; offset must == current size; -> {received})
GET    /api/v1/uploads/{id}                         (-> {received}, for resume)
POST /api/v1/signatures/reserve
POST /api/v1/signatures/{public_id}/stamp        (body: application/pdf; ?reason=&issued_place=&stamps=<url-encoded JSON array>. Each array entry {"page":1,"x":0.62,"y":0.80,"w":0.30}: page 1-based (0/absent = last page), x,y = top-left of the QR box as page fractions, w = width fraction. The server draws one caption+QR stamp per entry: name/jabatan/NIP come from the verified account (never the client); "Dikeluarkan di <kota>" is the ?issued_place= value for this signature (omitted if absent); the date is server time in Asia/Jakarta. Returns the PDF, page count unchanged. If ?stamps= is absent it falls back to a single stamp from ?page=&x=&y=&w=. 422 if the PDF cannot be processed or an entry cannot be placed.)
PUT  /api/v1/signatures/{public_id}/document     (body: application/pdf, OR ?upload_id=<id> with no body. Large-document tiers, docs/large-files.md: <= PQC_MAX_VERIFY_MB -> strict re-verify + store; larger -> store-only, verification_status "stored_unverified", SHA-512 recorded, no cert linkage.)
GET  /api/v1/signatures/{public_id}
GET  /api/v1/signatures/{public_id}/download
GET  /api/v1/me/signatures
```
Client sign flow: `reserve` → `stamp` (sign the returned bytes on-device) → `document`.
For a document over `PQC_MAX_STAMP_MB`, skip `stamp` (413) and submit the
on-device-signed PDF straight to `document`; over `PQC_MAX_VERIFY_MB` the
server records it store-only. Push large PDFs through `/api/v1/uploads` in
chunks, then `document?upload_id=` / `stamp?upload_id=`.

## Public verification
```
GET  /                              (browser upload page — verification-only service only)
POST /api/v1/verify                 (multipart 'file'; no auth)
GET  /v/{public_id}                 (QR landing page)
GET  /v/{public_id}/document        (authoritative signed PDF behind the QR)
GET  /api/v1/public/signatures/{public_id}
GET  /api/v1/public/ca/root.crt
GET  /api/v1/public/ca/chain.pem
GET  /api/v1/public/ca/crl.pem
```

Run `api --verify-addr :8098` (or `PQC_VERIFY_ADDR=:8098`) to also serve a
**verification-only** site on a second port: just the routes above, no
`/auth`, `/signatures`, `/devices`, or `/admin`. Publish it separately from
the signing API when only verification should be reachable.

## Admin
```
GET    /api/v1/admin/capabilities                ({lab_issuer, role})
GET    /api/v1/admin/admins                       (super admin only: admin roster)
POST   /api/v1/admin/admins                       (super admin only: {username,password} -> active admin)
PATCH  /api/v1/admin/admins/{id}                  (super admin only: {password} reset, {status:"active"|"disabled"})
DELETE /api/v1/admin/admins/{id}                  (super admin only)
GET    /api/v1/admin/accounts
POST   /api/v1/admin/accounts/{id}/approve        (CLIENT accounts only)
POST   /api/v1/admin/accounts/{id}/disable        (client only; cascade: revoke all certs + republish CRL)
POST   /api/v1/admin/accounts/{id}/enable         (client only)
PATCH  /api/v1/admin/accounts/{id}                (client only; {full_name, organization})
DELETE /api/v1/admin/accounts/{id}                (client only; cascade; tombstone if it has signatures)

Admin accounts are managed ONLY via /admin/admins (super admin, full CRUD).
The /admin/accounts/* mutation routes return 403 for any admin/superadmin
target. In the /admin console the super admin sees ONLY the "Admin" view;
regular admins see the client-account views and no "Admin" menu.
GET    /api/v1/admin/enrollments
POST   /api/v1/admin/enrollments/{id}/approve
GET    /api/v1/admin/enrollments/{id}/export
POST   /api/v1/admin/enrollments/{id}/certificate
POST   /api/v1/admin/enrollments/{id}/issue-lab   (only when Config.LabIssuer is set)
POST   /api/v1/admin/certificates/{id}/revoke
POST   /api/v1/admin/crl/import
GET    /api/v1/admin/audit-events
```
All `admin/*` routes require an admin role; all except `capabilities` also
require MFA (or `PQC_MFA_NOT_REQUIRED=1` on a dev receiver).

## Forbidden

There must be no `POST /api/v1/sign` and no `POST /api/v1/users/{id}/sign`
(§17.5).

## Shared verification result

`POST /api/v1/verify` and the local verifiers all return the JSON produced by
`core/verification` (`verification.Result`) — see §11.3 / §16.2. The server
adds `registered`, `signer_name`, `position`, `nip`, `device_label`,
`certificate_status`, `server_received_at`.
