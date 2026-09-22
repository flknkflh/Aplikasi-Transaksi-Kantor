# ADR-0008: Per-account certificate expiry view and renewal

**Status:** Accepted (2026-09-22). Follows up on the security-review answers about certificate
lifetime: certificates already had an enforced expiry (default 1 year, checked against the
current time on every strict/public verification), but the admin console had no way to see a
certificate's expiry date, and no way to renew one — an admin had to already know a
`certificate_id` (from the audit log or an upload response) just to revoke it.

## Decision

1. **`GET /api/v1/admin/accounts/{id}/certificates`** — the certificates for one account, each
   with `not_before`, `not_after`, a computed `expired` flag, `status`, and (when revoked)
   `revoked_at`/`rev_reason`. Reuses the existing `CertificatesByAccount` store method — no
   schema change. Gated by `clientTarget` (admin-only, refuses an admin/superadmin id target,
   same guard every other `/admin/accounts/{id}/*` route already uses).
2. **`POST /api/v1/admin/accounts/{id}/certificates/{cert_id}/renew`** — "renew" cannot mean
   editing `NotAfter`: an X.509 certificate is an immutable signed document. It means issuing a
   **fresh** certificate through the exact pipeline every certificate already goes through:
   - Look up the enrollment that produced the target certificate, to get its **CSR** (the
     device's existing public key — nothing changes on the device side, no new key, no browser
     interaction needed).
   - Create a **new** `Enrollment` row reusing that CSR, with status `approved` directly (an
     admin explicitly requested this for an account they already manage, so the normal
     submit→approve step is skipped).
   - That enrollment immediately appears in the existing **Perangkat** (devices/enrollments)
     view, with its existing "Unduh CSR" / "Terbitkan (lab CA)" / "Unggah sertifikat" actions —
     no new UI needed there at all. The admin follows the same steps as any first-time issuance:
     export the CSR, get it (re-)signed by the CA (offline/air-gapped in production; the lab
     issuer in dev), upload the result.
3. **The old certificate is deliberately left untouched — not revoked, not marked in any special
   way.** Two reasons, both load-bearing:
   - The server's own strict verification (`verify.go`) rejects anything whose stored `Status`
     is not `active`. Revoking the old certificate on a routine renewal would retroactively make
     every signature it ever legitimately made start reading "revoked" — exactly the outcome
     account-disable/delete *intentionally* cause (a real compromise/loss event), which renewal
     is not.
   - `CertificateByDevice` (what every signing/stamping code path already calls to find "the"
     certificate for a device) picks the one with the **latest `NotBefore`**. The instant the new
     certificate is bound, it becomes the one used for future signing with zero other code
     changes — the old one simply stops being selected, while remaining valid for anything it
     already signed until its own `NotAfter`.
4. **UI**: the account list's certificate-count cell (`2/3`) is now a toggle button; clicking it
   expands an inline row per account showing each certificate — device, serial (truncated, full
   value in the title tooltip), issued date, **expiry date** (in red once past), status pill, and
   a "Perpanjang" button on active certificates. Renewing shows a confirmation explaining the old
   certificate is *not* revoked, then jumps to the Perangkat view where the new enrollment is
   waiting. No certificate list is ever fetched until its row is expanded (lazy-loaded, one panel
   open at a time).

## Consequences — read these

- **Renewal only prevents an interruption if it happens before the old certificate's `NotAfter`.**
  If it has already expired, verification of NEW signatures made with it already fails (by
  design, per the earlier checklist answer on certificate lifetime) — renewing after the fact
  gets the person signing again, but does not retroactively fix anything that already failed
  verification while they had no valid certificate. There is no reminder/notification for
  upcoming expiry yet; an admin has to open the account's row to notice one is close.
- Reusing the CSR means the renewed certificate carries the **same public key** as before. This
  is normal PKI practice (many CAs support CSR reuse) and requires no device-side change, but a
  deployment that wants fresh key material on every renewal (stronger key-compromise hygiene at
  the cost of the device needing to regenerate and resubmit a CSR) would need a different flow —
  not built here, since nothing in the original enrollment/signing design required it either.
- Because the old certificate stays `active`, an account can have **more than one** row reading
  "aktif" in the certificate list at once — expected and correct (the newest by `not_before` is
  the one actually used for new signing; the UI shows every one so the admin isn't confused about
  why an older row is still marked active).

## Verification

`ttd/server/internal/api`: `certificates_test.go` — the list endpoint returns expiry/status for
a freshly issued certificate (`expired:false`, correct `not_after`) and is refused to a non-admin
token; renewal creates a pre-approved enrollment reusing the same device, that enrollment shows
up in `GET /admin/enrollments`, the original certificate's status is unchanged afterward, and
renewing/listing through the wrong account id 404s (IDOR check — a certificate cannot be renewed
or read through an account it does not belong to). Full existing suite green on both the
in-memory store and a real Postgres 17 container. Full legacy browser e2e (`run.mjs`, 55 checks,
including the CSP guard tests) re-run against the rebuilt `adminui.html` — unchanged pass,
confirming the new certificate-detail panel introduced no CSP violations and every existing flow
still works.
