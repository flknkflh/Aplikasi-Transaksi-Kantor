# ADR-0005: Super admin with a separated login mechanism

**Status:** Accepted (2026-09-22).

## Context

The archive app (ADR-0004) needed one more role above the central admin: someone whose only
job is to create/manage **admin** accounts, so that "who can create an admin" is not itself
just another admin capability. The owner asked for this super admin to log in through a
**mechanism separated** from ordinary/admin login, and to be **created automatically** the
first time the server runs — no built-in password shipped in the code.

## Decision

1. **One super admin, auto-created on first start.** `ensureSuperAdmin()` runs on every boot;
   if no super-admin account exists yet it creates the single account named by
   `PQC_SUPERADMIN_USERNAME` (default `superadmin`). If `PQC_SUPERADMIN_PASSWORD` is set it
   seeds that as the initial password (still forced to change — see below); otherwise a random
   password is generated and printed **once** to the server log. It can be disabled or deleted
   by no one — there is no delete route for it and it is excluded from the admin roster.
2. **Separate login surface, not a role flag on the normal path.** A dedicated page (`/superadmin`)
   and API namespace (`/api/v1/superadmin/*`) — `POST /login`, `/setup/begin`, `/setup/confirm`,
   `/verify`, `GET /me`, `POST /change-password`, and the admin-roster CRUD
   (`/admins`, `/admins/{id}`). The ordinary `POST /auth/login` explicitly refuses a super-admin
   account (`hLogin` checks `Role == RoleSuperAdmin` first and returns 403 with
   `{"superadmin_login": true}` so the UI can point the user at the right door) — there is no
   path by which a super-admin session is issued from the normal login form.
3. **Password + mandatory TOTP**, not password alone. First login after creation (or after a
   password reset) is a **setup** step: choose a new password (`saMinPassword` = 12 chars) and
   enroll an authenticator app (`otpauth://` URI + QR + the raw secret, RFC 6238, 30 s step, ±1
   step drift, replay blocked via a persisted `lastStep`). Every login after that is
   password → 6-digit TOTP code; there is no "remember this device" or backup-code bypass.
   Five failed attempts lock the account for 15 minutes (`saMaxFailures`, `saLockFor`).
4. **Cryptographically separate tokens**, not just a separate route guard. Super-admin session
   tokens are signed with keys derived from the same `JWTSecret` via HKDF-SHA256 but with
   distinct `info` strings per purpose (`pqc-sa-step/v1` for the in-progress
   login/setup challenge, `pqc-sa-access/v1` for the final session, `pqc-sa-totp/v1` to seal the
   TOTP secret at rest). An ordinary/admin JWT is signed with a different key entirely and is
   rejected by every `/api/v1/superadmin/*` handler even if its claims were forged to say
   `role: superadmin` — the check is "was this token signed with the super-admin access key",
   not "does this token's role field say so". The reverse holds too: a super-admin access token
   is not accepted by the ordinary `authed()` path, so it cannot reach `/admin/*` or any
   office/archive route. Sessions are short — `saDefaultSession` = 15 minutes — and the token
   is kept in JS memory only in the `/superadmin` page (never `localStorage`/`sessionStorage`),
   with a visible countdown.
5. **Scope: admin management only.** The super admin's entire surface is create / list /
   disable / reset-password / delete on **admin** accounts. It cannot see or touch archive
   items, offices, office members, or ordinary users; those stay behind the regular
   `admin`/`superadmin`-via-`authed()` routes used by the archive app (ADR-0004), which an
   ordinary admin account reaches through the normal `/admin` console.
6. **A separate first-admin bootstrap for dev/seed use**, unrelated to the super admin:
   `ensureBootstrapAdmin()` creates one ordinary admin from `PQC_BOOTSTRAP_ADMIN_EMAIL` /
   `PQC_BOOTSTRAP_ADMIN_PASSWORD` only if no admin account exists yet. This replaces the old
   pattern where a `PQC_SUPERADMIN_USERNAME`/`PASSWORD` pair both created *and* logged into a
   demo admin; that conflated "the permanent super-admin identity" with "a convenience login
   for local demos", which is what motivated separating them here.

## Consequences — read these

- **Two credentials to manage in production**, not one: the super-admin password + TOTP seed,
  and (if used) the bootstrap admin's password. The initial super-admin password appears in the
  log exactly once; if it is lost before first setup, the only recovery is a direct database
  fix (there is no "forgot password" flow for the super admin by design — it is the account
  that resets everyone else's).
- **Losing the TOTP device locks the super admin out.** There is no backup-code or email-reset
  path in this version; recovery again means a direct database intervention (clear
  `superadmin_security` to force a fresh setup). Documented here rather than papered over with
  a bypass, since a bypass would undercut the reason TOTP was requested.
- **The `/admin` console no longer has an "Admin" management view for the super admin** — that
  console is for ordinary admins (archive/office/member views) only; admin-roster management
  moved entirely to `/superadmin`. An operator following old docs/screenshots for
  `/api/v1/admin/admins` needs to be pointed at `/api/v1/superadmin/admins` instead
  (`ttd/docs/api.md` was updated).
- Rate limiting and lockout apply per super-admin account (there is only one), so a stray
  script hammering `/api/v1/superadmin/login` locks out the real operator for 15 minutes too;
  acceptable for a single low-traffic account, worth revisiting if this becomes multi-tenant.

## Verification

`ttd/server`: `superadmin_test.go` (auto-create + forced setup, wrong-door rejection from
`/auth/login`, token non-interchangeability in both directions, TOTP accept/replay-reject,
setup validation, lockout after 5 failures, change-password + admin-management-only scope, CSP
on the `/superadmin` page, bootstrap-admin-only-when-none-exists), plus the existing
`accounts_test.go`/`office_test.go` updated to call `/api/v1/superadmin/admins`.
`ttd/web/e2e/superadmin.mjs`: real Chrome against the Docker stack — reads the auto-generated
password from the container's first-boot log, runs the full setup ceremony (password + TOTP
enrollment via an independent JS TOTP implementation cross-checked against the server), logs
in, creates/disables/resets/deletes admin accounts, verifies the CSP, and persists its session
state so repeat runs don't need to consume a fresh super-admin ceremony each time.
