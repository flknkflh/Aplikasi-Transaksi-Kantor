# ADR-0012: Password length ceiling + reject known-default secrets at startup

**Status:** Accepted (2026-09-25). Security checklist items #6 and #9 (see docs/adr/0006 and
docs/adr/0007 for the earlier batches of the same checklist).

## Context

Two gaps from the checklist, both about trusting input the server should never silently accept:

- **#6 — password length policy.** A minimum (8 chars ordinary accounts, 12 for the super admin,
  `saMinPassword` in superadmin.go) already existed at every password intake handler. There was no
  **maximum**. Argon2id's hashing cost scales with input size, so an unbounded password body is a
  hashing-cost denial-of-service vector: a small HTTP request, disproportionate CPU work.
- **#9 — reject default secrets at startup.** `ttd/deploy/local/.env.example`,
  `deploy/office/docker-compose.yml`, and `ttd/deploy/local/docker-compose.yml` all ship convenience
  DEV-default secrets directly as `${VAR:-literal-placeholder}` fallbacks (e.g.
  `local-prototype-secret-change-me-0123456789`, `admin12345`, `ledger_dev_only`). Nothing stopped a
  real deployment from silently starting with one of these exact, repo-public values if an operator
  forgot to override them — the length check on `PQC_JWT_SECRET` (≥16 bytes) does not catch this;
  most of these placeholders are already longer than that.

## Decision

**#6:** Added `auth.MaxPasswordLength = 128` (`ttd/server/internal/auth/auth.go`). Enforced in two
places, deliberately redundant:

1. Inside `HashPassword`/`VerifyPassword` themselves — the auth package's own trust boundary, so no
   future call site can skip it by forgetting a check.
2. At every intake handler that already had the minimum check (`handlers.go` register,
   `accounts.go` admin creation + password reset, `superadmin.go` `checkNewPassword`), so the
   rejection is a clean 400 with a clear message instead of an opaque 500 from the auth layer.

**#9:** Added `rejectInsecureSecret`/`looksLikeDefaultSecret` (duplicated in both
`ttd/server/cmd/api/main.go` and `api/main.go` — two independent Go modules, no shared runtime
package between them) — checked at startup, hard-fails (`log.Fatal`/`os.Exit(1)`) if a
security-relevant config value contains an obvious placeholder marker (`change_me`, `change-me`,
`changeme`, `dev_only`, `dev-only`, `example`, `placeholder`, `insecure`, plus exact matches for a
few short common ones like `admin12345`/`pqc`/`postgres`).

Checked: `PQC_JWT_SECRET`, `PQC_SUPERADMIN_PASSWORD`, `PQC_BOOTSTRAP_ADMIN_PASSWORD`,
`PQC_OFFICE_SECRET` (ttd/server); `DATABASE_URL`, `MINIO_SECRET_KEY`, `OFFICE_PROXY_SECRET`,
`KEYSTORE_KEK` (ledger api).

**The escape hatch:** `ALLOW_INSECURE_DEV_SECRETS=true` (read directly via `os.Getenv`, not
threaded through `api.Config`/`config.Config` — it only ever gates this one startup check) turns
the fatal error into a logged warning instead. `deploy/office/docker-compose.yml` and
`ttd/deploy/local/docker-compose.yml` now set it explicitly (`${ALLOW_INSECURE_DEV_SECRETS:-true}`)
so local/dev usage keeps working exactly as before — but the insecurity is now a visible, commented
line in the compose file instead of an invisible default a real deployment could inherit by doing
nothing. Removing that one line (or overriding the env var) is what a real, non-dev deployment of
either compose file should do, alongside actually setting real values for the env vars it currently
falls back on.

## Verification

- `go test ./ttd/server/...` and `go test ./api/...` green after both changes (no test constructs a
  password/secret near either boundary, so the stricter checks didn't require new fixtures).
- Live-verified against the running `deploy/office` dev stack: rebuilt and restarted `ttd` and
  `ledger-api`, confirmed the startup logs show exactly the expected warning for each known
  placeholder value (`PQC_JWT_SECRET`, `PQC_BOOTSTRAP_ADMIN_PASSWORD`, `PQC_OFFICE_SECRET`,
  `DATABASE_URL`, `MINIO_SECRET_KEY`, `OFFICE_PROXY_SECRET`, `KEYSTORE_KEK`), and that both services
  still started and served traffic normally with `ALLOW_INSECURE_DEV_SECRETS=true` set.
- Not separately tested: actually removing `ALLOW_INSECURE_DEV_SECRETS` and confirming a hard
  `os.Exit(1)`/`log.Fatal` — straightforward from reading the code path (same `check`/
  `rejectInsecureSecret` function, `allowInsecureDev` is the only branch), but noted here as an
  honest gap rather than claimed as directly observed.

## Consequences

- The marker-based check is deliberately broad (substring match on `change`-style words), not an
  exact denylist — it will also reject a real secret an operator picks that happens to contain one
  of these words (e.g. a password containing literally "changeme" as a joke). That is the intended
  trade-off: false positives are a minor annoyance fixed by picking a different value; false
  negatives (a real deployment silently running on a leaked repo default) are the actual risk being
  guarded against.
- This does not — and cannot — catch a *weak but not-a-known-placeholder* secret (e.g. an operator
  setting `PQC_JWT_SECRET` to their own short guessable phrase that isn't one of these markers). The
  existing ≥16-byte length check is the only defense there; strength/entropy checking is out of
  scope for this change.
