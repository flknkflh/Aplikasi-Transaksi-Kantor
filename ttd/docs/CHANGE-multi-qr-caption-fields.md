# Change spec: multi-QR stamps, mandatory e-sign caption, signer profile fields

Status: **client (desktop + Android) done in this repo. Server side done.**
Deploy order: **server first**, then the new apps. The contract below is
backward-compatible on the server so old apps keep working against the new
server during the transition.

> **Amendment (server impl):** "Dikeluarkan di <kota>" is **per signature**,
> not a fixed account field. It is passed to `POST .../stamp` as the
> `issued_place` query param (next to `reason`), not sent at registration.
> Registration keeps only `position` + `nip` (the signer's fixed identity).
> The server still accepts and ignores a stale `issued_place` in the register
> body, so the current clients do not break; a follow-up client change moves
> the "Kota" field from the register pane to the sign/placement step and sends
> it as `?issued_place=`. Sections 2a / 2c / 3 below are updated to match;
> 2b now also lists `issued_place`.

---

## 1. What changes where

| Area | Client (apps — already done) | Server (this doc's TODO) |
|---|---|---|
| Registration form | +Jabatan, +NIP inputs; sent in the register call (a stale +Kota input is still there client-side, ignored by the server — see Amendment) | `hRegister` accepts + stores `position` + `nip`; `Account` model + DB migration |
| Login | unchanged (email + password) | unchanged |
| Placement UI | place 1..N QR spots ("Tambah titik QR"), send a list | `/stamp` accepts a `stamps` JSON array (falls back to single `page/x/y/w`) |
| Stamp graphic | — (drawn on the server) | each stamp = **caption block + QR** (was bare QR); caption text from the verified account; **date = server time** |
| Seed data | — | `deploy/local/seed.sh` fills the 3 new fields for `admin@local` + `user@local` |
| Verify page / record | shows the extra fields if present | `publicRecord` may expose `position` / `nip` (optional) |

---

## 2. API contract

### 2a. `POST /api/v1/auth/register`  (JSON body — add 2 optional fields)

```jsonc
{
  "email": "...", "password": "...",
  "full_name": "Gita Aurora, S.Ap., M.P.A.",   // name WITH academic titles
  "organization": "Deputi Bidang ...",          // unit / instansi (existing)
  "display_name": "Gita Aurora",                // existing
  "position": "Plt. Asisten Deputi Perumusan dan Koordinasi Kebijakan Penerapan Akuntabilitas Aparatur dan Pengawasan",
  "nip": "198704012011012005"
  // NOTE: "issued_place" is accepted for compatibility but ignored — it is a
  // per-signature value now, see 2b.
}
```
Both new fields optional (empty string when absent). No response shape change.

### 2b. `POST /api/v1/signatures/{public_id}/stamp`

Body: the raw PDF (unchanged). Query params:

- `reason` — unchanged.
- **`issued_place`** — NEW, optional. The city for the caption's
  "Dikeluarkan di <kota>" line, for *this* signature. Absent ⇒ the line is
  omitted. Not stored on the account.
- **`stamps`** — NEW. URL-encoded JSON array; each entry is one QR box:
  ```json
  [{"page":1,"x":0.62,"y":0.80,"w":0.30},
   {"page":3,"x":0.10,"y":0.15,"w":0.22}]
  ```
  `x,y` = **top-left corner** of the box as a fraction of the page (origin
  top-left). `w` = box width as a fraction of page width. `page` 1-based;
  `0`/absent ⇒ last page.
- If `stamps` is absent, fall back to the existing single `page`, `x`, `y`,
  `w` params (one stamp). **Keep this fallback** so old apps still work.

Server draws one caption+QR stamp per entry and returns the augmented PDF
(`X-QR-Stamp: applied`, page count unchanged). Any entry that cannot be
placed ⇒ 422 with the existing Indonesian message.

### 2c. Stamp graphic (per placement)

A bordered white box, **landscape** (`stampAspect` = height/width ≈ **0.42** —
must match the clients' default box shape and `STAMP_ASPECT` constants).

Contents (`<full_name>` / `<position>` / `<nip>` from the **verified account
record**, never the client; `<issued_place>` from the `/stamp` request;
`<server date>` from server time):

```
Ditandatangani secara elektronik oleh:            ┌─────────┐
<full_name>                    (bold)              │   QR    │
<position>                     (wrapped to width)  │         │
NIP. <nip>                                         └─────────┘
Dikeluarkan di <issued_place>   (from ?issued_place=)
Pada tanggal <server date>
```

- **Date = server time at stamp**, `Asia/Jakarta`, formatted Indonesian:
  `2 Januari 2006` → e.g. `8 September 2026`. Add a small `idMonth()` helper
  (`[]string{"Januari",...}`). The Alpine runtime image needs `tzdata`
  (`apk add --no-cache tzdata` in `deploy/local/Dockerfile`); if
  `time.LoadLocation("Asia/Jakarta")` errors, fall back to `time.FixedZone("WIB", 7*3600)`.
- QR content = unchanged (`s.qrTarget(r, publicID)`).
- Lines with an empty field are skipped (e.g. no NIP ⇒ no "NIP." line).
- Re-add the text renderer removed earlier: `golang.org/x/image/font`,
  `font/opentype`, `font/gofont/goregular` + `gobold`, `math/fixed`. Wrap the
  `position` line to the available width. `go mod tidy` will pull `x/image`
  back as a direct dep — add it to `LICENSES/THIRD_PARTY_NOTICES.md`.

---

## 3. Server TODO (files)

1. **`server/internal/store/store.go`** — `Account` gains `Position`, `NIP`
   `string` (no `IssuedPlace` — that is per-signature, see Amendment).
2. **`server/internal/store/migrations/0005_signer_fields.{up,down}.sql`** —
   `ALTER TABLE accounts ADD COLUMN position TEXT NOT NULL DEFAULT ''`, same
   for `nip`. Down: drop them.
3. **`server/internal/store/postgres.go`** — add the 2 cols to `acctCols`,
   the INSERT, and every `rowToAccount`/scan. **`memory.go`** — `CreateAccount`
   already copies the whole struct, nothing to do.
4. **`server/internal/api/handlers.go`** — `hRegister` reads `position` and
   `nip` from the body into the new `Account` fields (a stale `issued_place`
   in the body is ignored).
5. **`server/internal/api/stamp.go`** — parse `stamps` query param (JSON
   array) → `[]stampPlacement`; keep the single-param fallback. Make `stampQR`
   take `[]stampPlacement` and emit N images in one `pdfcpu.Create` call (one
   JSON doc, images grouped by page). Fetch the signer `Account`
   (`s.st.Account(c.Sub)`) for `FullName/Position/NIP`; read `issued_place`
   from the query; pass those + `idDate(jakartaNow())` into the composer.
6. **`server/internal/api/stamppng.go`** — replace `buildStampPNG(qrContent,
   widthPx)` with `buildStampPNG(qrContent string, cap captionData, widthPx int)`
   that renders the caption block + QR per §2c. `captionData{FullName,
   Position, NIP, IssuedPlace, DateText}` (`IssuedPlace` filled from the
   request, not the account). Bump `stampAspect` to `0.42`.
7. **`server/internal/api/verifpage_test.go` / `qrtarget_internal_test.go`**
   — update `TestStampThenSubmit` etc. for the `stamps` param + the new
   aspect; add a multi-stamp test (2 entries ⇒ 2 images embedded, page count
   unchanged, still strict-verifies).
8. **`server/internal/api/qrpage.go`** (optional) — `hVerifyPage` shows
   `position` / `nip` rows from `publicRecord`.
9. **`server/internal/api/handlers.go` `publicRecord`** (optional) — include
   `position`, `nip`.
10. **`deploy/local/Dockerfile`** — `apk add --no-cache tzdata` on the
    runtime stage.
11. **`deploy/local/seed.sh`** — add `position`, `nip` to the admin + user
    register payloads, e.g.
    `"position":"Administrator Sistem","nip":"000000000000000000"` for admin
    and the pusat-example values for the user (no `issued_place` — per
    signature now).
12. **`docs/api.md`** — document the register fields + `stamps` param.
13. Run `gofmt`, `go test ./...` in `server/`, `bash tools/acceptance.sh`
    (all must stay green), then rebuild the container:
    `cd deploy/local && docker compose up -d --build` and re-seed if the DB
    is fresh.

### Verification after server deploy

```bash
# single (old-app path) still works:
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  "http://localhost:8099/api/v1/signatures/PID/stamp?x=0.6&y=0.8&w=0.3" ...   # 401 without auth is fine; use a real token in an e2e

# multi (+ per-signature place):
S='[{"page":1,"x":0.55,"y":0.6,"w":0.3},{"page":1,"x":0.1,"y":0.1,"w":0.2}]'
curl ... --data-binary @doc.pdf \
  "http://localhost:8099/api/v1/signatures/PID/stamp?reason=Persetujuan&issued_place=Jakarta&stamps=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$S")"
```
Then `tools/acceptance.sh` should still be 7/7.

---

## 4. Client side (already implemented here)

- Desktop `frontend/dist/index.html`: register pane has Jabatan / NIP / Kota;
  `#scPlace` has **"Tambah titik QR"** (snapshots the current box → list,
  faint marker drawn) + **"Tanda tangani (N titik)"**; sends
  `SignPDF(..., placementsJSON)`.
- `apps/windows/internal/apiclient/client.go` `Stamp(publicID, pdf,
  []StampPlacement, reason)` → `?stamps=<json>`.
- `apps/windows/internal/appcore/appcore.go` `SignPDF(..., placementsJSON string)`
  → `[]QRPlacement`.
- `apps/windows/cmd/pqcsign-desktop/app.go` `SignPDF(..., placementsJSON string)`,
  `Register(..., position, nip, issuedPlace string)`.
- Android `net/ApiClient.kt` `stamp(publicId, pdf, List<StampPlacement>, reason)`,
  `register(..., position, nip, issuedPlace)`.
- Android `app/AppCore.kt` `signPdf(uri, reason, signerName, List<StampPlacement>)`,
  `register(..., position, nip, issuedPlace)`.
- Android `MainActivity.kt`: register screen fields; placement screen
  "Tambah titik QR" + counter.

If the server is still on the old contract, the new apps' multi-stamp call
fails (old server ignores `stamps`, draws nothing or errors). Update the
server first.

### 4a. Client follow-up (not yet done) — per-signature "Dikeluarkan di"

Per the Amendment, the "Kota / Dikeluarkan di" input must move from the
**register** pane to the **sign / placement** step, and be sent to `/stamp`
as `?issued_place=<kota>` next to `reason`. Until that lands:

- the clients still collect "Kota" at registration; the server ignores it, so
  nothing breaks, but the value has no effect;
- the "Dikeluarkan di" caption line is blank unless the caller adds
  `?issued_place=` by hand.

Touch points: desktop `frontend/dist/index.html` (move the field, pass it
through `SignPDF`), `apps/windows/internal/apiclient/client.go` `Stamp(...)`
(add an `issuedPlace` arg → `q.Set("issued_place", ...)`), the appcore/app
wrappers, and Android `net/ApiClient.kt` `stamp(...)` + `AppCore.signPdf(...)`
+ `MainActivity.kt`.
