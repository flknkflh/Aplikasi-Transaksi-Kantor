# ADR-0007: Failed-login lockout and opt-in TOTP for ordinary admins

**Status:** Accepted (2026-09-22). Closes two "Prioritas Tinggi" items from the pre-launch
security checklist review: missing rate limiting on `/auth/register` and `/office/*`, and no
brute-force protection on the central admin's account.

## Context

The security review found two gaps in the same area — account/endpoint abuse:

1. `POST /api/v1/auth/register` and the entire `/office/*` proxy (archive upload, list, admin
   console traffic) had no rate limiting at all, despite a comment in the ledger-api code
   assuming the TTD layer handled it.
2. The **central admin** account — the one role that can see every office's archive — logged in
   with password only: no MFA, and no lockout after repeated failed attempts (only a generic
   per-IP rate limit shared with every other login). The super admin (ADR-0005), which only
   manages the admin roster and cannot see any archive data, already had mandatory TOTP; the
   more sensitive account had the weaker login.

Asked the owner which to build for admin hardening: TOTP mandatory for every admin (like the
super admin, forcing existing/demo admins through a setup ceremony) or lockout mandatory + TOTP
opt-in. Chose **lockout mandatory, TOTP opt-in** — closes the brute-force gap for every admin
immediately with no behavior change for existing accounts, and gives admins who want MFA a way
to turn it on without a breaking migration for everyone else.

## Decision — rate limiting

1. New buckets in `RateLimits` (`ratelimit.go`/`api.go`): `RegisterPerIP` (default 5/min) and
   `OfficePerAccount` (default 120/min — generous enough that a fast connection sending 8 MiB
   archive chunks back to back isn't throttled, ~150 Mbps sustained at that cap, while still
   capping a runaway script far below that).
2. `POST /api/v1/auth/register` is now `s.limit(s.rlRegister, byIP, ...)`, matching how `/login`
   was already limited.
3. The entire `/office/` proxy handler is wrapped `s.user(s.limit(s.rlOffice, byAccount, ...))`
   — keyed per account (not per IP), because every request already goes through the single TTD
   origin behind one IP from the ledger-api's perspective; per-IP would either be too loose (one
   IP, many accounts) or punish everyone behind the same NAT.

## Decision — admin lockout + opt-in TOTP

1. **Lockout is unconditional**, no admin action needed: five wrong passwords, or five wrong
   TOTP codes for an admin who enabled it, locks the account for 15 minutes
   (`saMaxFailures`/`saLockFor` — the exact constants and policy the super admin already uses).
   Checked in `hLogin` before the password is even verified, so a locked account fails fast.
2. **TOTP is opt-in, self-service.** An admin turns it on for their own account from the
   `/admin` console ("Keamanan akun saya", in Operasi & Utilitas): `POST
   /api/v1/admin/security/totp/begin` generates a secret (QR + manual key, same UX as the super
   admin's enrolment), `POST /api/v1/admin/security/totp/confirm {code}` turns it on. Disabling
   (`POST /api/v1/admin/security/totp/disable {code}`) requires a **currently valid** code, not
   just the session token, so a stolen bearer token alone cannot silently turn MFA off.
3. **No new table.** Both features reuse `store.SuperSecurity` / the `superadmin_security` table
   (ADR-0005) — it is keyed by `account_id` with no role constraint, so it already fit: lockout
   fields (`FailedCount`, `LockedUntil`) and TOTP fields (`TOTPSecret`, `TOTPEnabled`,
   `LastStep`) work identically for an admin row and the super admin's row. Despite the type's
   name, it is now step-up login state for *any* account, not only the super admin's — noted in
   the Go doc comment.
4. **Separate keys, still.** The admin's TOTP secret is sealed under its own derived key
   (`adminTOTPAEAD`, HKDF info `pqc-admin-totp/v1`) — a different key from the super admin's
   (`pqc-sa-totp/v1`). The second-login-step challenge is signed with its own signer
   (`adminMFAStep`, HKDF info `pqc-admin-mfa-step/v1`) — different from the super admin's
   `saStep` and from the ordinary access-token signer. None of an admin's TOTP secret, an
   admin's step token, a super admin's TOTP secret, or a super admin's step token are
   interchangeable with each other, continuing the key-separation approach ADR-0005 used.
5. **The final session token is unchanged**: after the (optional) TOTP step, `hLogin` /
   `hLoginTOTP` both issue the exact same kind of token as before
   (`s.signer.Issue(a.ID, a.Role)`). Nothing downstream — `/admin/*`, the `/office/*` proxy, the
   `s.admin()` middleware — needed to change; TOTP is purely an extra gate in front of the
   existing login, not a new session type.
6. **Recovery path**: `POST /api/v1/superadmin/admins/{id}/reset-security` (super admin only)
   clears an admin's lockout and disables their TOTP in one action — for a lost authenticator
   device or a false-positive lockout. Surfaced in the super-admin console as a "Reset keamanan"
   button per admin row, alongside a Keamanan column showing `terkunci`/`TOTP` status.

## Consequences — read these

- **A Postgres foreign-key issue, found and fixed while building this.** Because a
  `superadmin_security` row can now exist for an ordinary admin (as soon as they log in once,
  `PutSuperSecurity` upserts it to clear the failure counter), deleting that admin
  (`DELETE /api/v1/superadmin/admins/{id}`) started failing its `REFERENCES accounts(id)`
  constraint and silently falling back to the "tombstone" (disable-instead-of-delete) path —
  changing a real delete into a soft one without the caller asking for that. Fixed in
  `Postgres.DeleteAccount`: the security row is deleted first. Caught by the existing
  `TestAdminManagedBySuperAdmin` test when run against a real database — a reminder that this
  suite is only exercised against Postgres when `PQC_TEST_DATABASE_URL` is set; it is silent
  against the in-memory store, which has no foreign keys to violate.
- **No backup-code / recovery flow for an admin's own lost device** beyond the super admin's
  reset — same tradeoff already accepted for the super admin in ADR-0005, for the same reason
  (a bypass would undercut why TOTP was added).
- The admin roster endpoint (`GET /api/v1/superadmin/admins`) now also returns `totp_enabled`
  and `locked` per admin so the super admin's console can show them without a second call.
- Lockout is per-account, confirmed by test — one admin's lockout never blocks another's login,
  and it does not apply to ordinary `user`-role accounts (senders), whose blast radius is only
  their own uploads, not the whole archive.

## Verification

`ttd/server/internal/api`: `ratelimit_endpoints_test.go` (register floods to 429; `/office/*`
rate-limited per account, confirmed a second account is unaffected) and
`adminsecurity_test.go` (lockout after 5 failures with a positive `retry_after`, lockout does
not leak to other accounts or to plain users, full opt-in TOTP login round-trip including wrong
code / replay rejection, step-token non-interchangeability with an ordinary token and with the
super admin's own `/verify`, disable requires a live code, and the super-admin recovery route
clears both lockout and TOTP). Run against **both** backends: the in-memory store and a real
Postgres 17 container (`PQC_TEST_DATABASE_URL`) — the latter is what caught the `DeleteAccount`
foreign-key regression above. Full existing suite (55 checks) re-run through a real browser via
`ttd/web/e2e/run.mjs` against the rebuilt `adminui.html` (new two-step login UI, new "Keamanan
akun saya" panel) — unchanged pass, including the CSP guard tests
(`TestWebAppIsServedUnderAStrictCSP`, `TestBrowserClientSourceIsCSPClean`,
`TestSuperAdminPageIsServedUnderAStrictCSP`), confirming the new HTML/JS introduced no inline
scripts or CSP violations.
