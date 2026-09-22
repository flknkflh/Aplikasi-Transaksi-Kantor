# ADR-0010: Signature responses use an explicit field allowlist

**Status:** Accepted (2026-09-22). Closes checklist item 7 ("validasi output API" — the specific
example named, `hGetSignature`, plus its sibling `hMySignatures`).

## Context

A full pass over every `writeJSON` call in both `ttd/server/internal/api` and
`api/internal/httpapi` (the ledger service) found exactly two spots still serializing a raw store
struct instead of a curated response: `hGetSignature` (`GET /api/v1/signatures/{public_id}`) and
`hMySignatures` (`GET /api/v1/me/signatures`), both sending `store.Signature` (or a slice of it)
straight to the client. Every other endpoint in both packages already builds an explicit
`map[string]any` — `accountView`, `certView`, `publicRecord`, `submissionResult`,
`receiptResponse`, `archiveVerification`, and so on — this ADR brings the last two in line with
that existing, otherwise-consistent pattern, not a new one.

The same pass also checked every place an internal `err.Error()` is sent to the client (the other
half of "output validation" — an error message is output too). All of them were already safe:
`store.CreateAccount` collapses any insert failure into a fixed `"email already registered"`
(never a raw Postgres error), the CSR/certificate/CRL rejection messages are purpose-built
explanations meant to be read by the person who submitted the bad input, and the one place that
does forward a raw subprocess error (`hLabIssue`, the dev-only lab CA operator button) is
appropriately scoped to a trusted, already-authenticated admin who needs exactly that detail to
fix the issuance. No changes were needed on the error-message side; documented here because it
was checked, not skipped.

## Decision

1. **`signatureView(sig store.Signature) map[string]any`** (`handlers.go`) is the one place that
   turns a signature into what its owner sees: `public_id`, `device_id`, `certificate_id`,
   `cert_serial`, `cert_fingerprint`, `algorithm`, `pdf_profile`, `original_sha512`,
   `signed_sha512`, `client_claimed_signing_time`, `server_received_at`, `signed_size`,
   `verification_status`, `created_at`. Both `hGetSignature` and `hMySignatures` (per-item, over
   the list) now go through it.
2. **Left out on purpose:**
   - `StorageObjectKey` — an internal object-storage reference. The client has no legitimate use
     for it (the actual file comes back through `hDownload`, which resolves it server-side) and
     no business knowing the storage backend's key-naming shape at all.
   - `AccountID` — redundant on this endpoint (`hGetSignature`/`hMySignatures` already only ever
     return the caller's own signatures — the ownership check already happens in `hGetSignature`
     before this is called, and `hMySignatures` filters by the caller's id at the query).
3. **An explicit list, not a blocklist**, so a future field added to `store.Signature` does not
   silently start being exposed — it has to be added to `signatureView` on purpose, the same
   protection the existing DTOs elsewhere already give the endpoints they cover.
4. **Field names chosen to match what the client already tolerates.** `ttd/web/src/app.js`
   already reads these fields defensively — `g(r, 'PublicID', 'public_id')`,
   `g(r, 'VerificationStatus', 'verification_status')`, `g(r, 'CertSerial', 'cert_serial')` — a
   small helper that tries the raw-struct PascalCase name first, then falls back to snake_case.
   `signatureView`'s keys were picked to match that fallback exactly (`cert_serial`, not
   `certificate_serial`), so the switch needed **no client changes at all** — confirmed by
   re-running the existing e2e suite unmodified, not by inspecting the fallback and assuming it
   would work.

## Consequences — read these

- The response shape for these two endpoints changed (PascalCase struct fields → a fixed
  snake_case set). Any consumer that isn't the bundled web client and reads a field outside the
  new allowlist (most likely `StorageObjectKey`, if anything ever did) will need updating — none
  is known to exist; the bundled client and the e2e suite were the only consumers checked, and
  both already handled it via the fallback pattern described above.
- `GET /api/v1/signatures/{public_id}` (`hGetSignature`) turned out to have **no caller at all**
  in the bundled web client — searched and confirmed empty. Its output shape mattering to nobody
  today doesn't change the fix (a future caller shouldn't have gotten the raw struct either), but
  it's worth knowing the endpoint is currently only reachable directly, not through the UI.
- No schema or store-layer change — `store.Signature` itself is untouched; only what crosses the
  HTTP boundary changed.

## Verification

New test `ttd/server/internal/api/signatureview_test.go`:
`TestSignatureResponsesNeverLeakStorageObjectKeyOrAccountID` runs a real reserve→sign→submit flow
and asserts both `GET /api/v1/signatures/{public_id}` and `GET /api/v1/me/signatures` contain
none of `StorageObjectKey`/`storage_object_key`/`AccountID`/`account_id` and do contain the
expected allowlisted fields. Full existing suite green on both the in-memory store and a real
Postgres 17 container. Full legacy browser e2e (`ttd/web/e2e/run.mjs`, 55 checks) re-run against
the rebuilt client — unchanged pass, including the checks that read exactly these two endpoints
("server recorded exactly one signature", "history lists both signatures") — proving the real UI
keeps working with the new response shape, not just that the JSON is well-formed.
