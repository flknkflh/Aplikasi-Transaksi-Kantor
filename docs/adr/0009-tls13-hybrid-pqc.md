# ADR-0009: TLS 1.3 with hybrid post-quantum key exchange + HSTS

**Status:** Accepted (2026-09-22). Closes checklist item 19 ("security headers", specifically
the missing HSTS, and the demo stack having no TLS at all).

## Context

The security review found `deploy/office` serving plain HTTP with no reverse proxy — no
encryption in transit, and no `Strict-Transport-Security` header anywhere (sending it over plain
HTTP is a no-op anyway; there was nothing to send it *on*). The owner asked specifically for TLS
1.3 with **hybrid post-quantum key exchange** — consistent with the rest of this project's
posture: the application layer already does hybrid Ed25519+ML-DSA-65 signing (ADR-0004); the
transport layer had no equivalent.

## Decision

1. **Go's own `crypto/tls` already does this — no new dependency.** The installed toolchain
   (Go 1.27) offers `X25519MLKEM768` (X25519 + ML-KEM-768) as a supported TLS 1.3 key-exchange
   group by default since Go 1.24, and `SecP256r1MLKEM768` since Go 1.26. `CurvePreferences` is
   set explicitly in `ttd/server/cmd/api/main.go` (`tlsConfigFor`) to both hybrid groups plus
   classical `X25519`/`P-256` as fallback — explicit rather than relying on the implicit default,
   so it stays true regardless of a future Go version's default or a `GODEBUG=tlsmlkem=0`
   someone might set elsewhere. `MinVersion: tls.VersionTLS13` — TLS 1.2 is refused outright,
   per the explicit ask for "TLS 1.3"; there is no legacy-client audience for this app to protect.
2. **Additive, not a replacement.** The existing plain-HTTP listeners (`-addr`, `-verify-addr`)
   are untouched. Two new optional listeners (`-tls-addr`, `-verify-tls-addr`) serve the exact
   same `srv.Routes()` / `srv.VerifyRoutes()` handlers over HTTPS on their own address. Both are
   opt-in (nil unless a cert+key is configured), so every existing dev workflow, script, and test
   that talks to the plain HTTP port keeps working unmodified — verified by re-running the full
   existing e2e suites, not assumed.
3. **A self-signed certificate, generated on first boot, for the demo/local stack specifically.**
   A new tiny tool, `ttd/tools/tls-selfsigned` (ECDSA P-256, stdlib only — `crypto/x509` — no
   `openssl` binary added to the runtime image, matching the "pure Go, no cgo" approach the
   Dockerfile already documents for everything else in it), writes a cert+key into a persistent
   volume (`ttd_tls`) if none exists yet. `deploy/office/docker-compose.yml` sets `TLS_HOSTS`
   (default `localhost,127.0.0.1`) to drive it; set it empty to turn HTTPS off, or set
   `PQC_TLS_CERT_FILE`/`PQC_TLS_KEY_FILE` directly to bring a real certificate instead — see
   `deploy/office/TLS.md`.
4. **HSTS is sent, correctly conditioned on the connection actually being secure.** A new `hsts`
   middleware wraps both `Routes()` and `VerifyRoutes()`: `Strict-Transport-Security:
   max-age=63072000; includeSubDomains` is set when `r.TLS != nil` (native TLS) or
   `X-Forwarded-Proto: https` (behind a TLS-terminating reverse proxy — the same signal
   `hPublicServer` already used to report `https: true`/`false`). It is deliberately **not**
   sent over plain HTTP — doing so achieves nothing (browsers ignore HSTS on an insecure
   connection per spec) and would be misleading in a dual-listener setup where plain HTTP is
   still genuinely served. `includeSubDomains` is safe here because this is the one origin the
   whole app is served from (ADR-0003) — there is no other subdomain it would incorrectly cover.
   `preload` is deliberately omitted — see TLS.md's "Going further".

## Consequences — read these

- **No HTTP→HTTPS redirect.** Visiting the HTTP URL still serves the app in plaintext; nothing
  forces a visitor onto HTTPS. Two listeners running side by side, not a migration — see TLS.md
  for why, and what replaces this (a reverse proxy) for a real production rollout with a real
  domain and certificate.
- **The self-signed certificate will show a browser trust warning.** Expected for local/demo use,
  not acceptable beyond a LAN a small group trusts by hand — TLS.md spells out the upgrade path
  (a real internal CA or Let's Encrypt, then a reverse proxy in front).
- **TLS 1.3-only means no TLS 1.2 fallback, anywhere, on the HTTPS listeners.** Any client that
  cannot do TLS 1.3 cannot connect over HTTPS at all (it can still use the plain-HTTP listener,
  which is untouched). A deliberate choice per the explicit "TLS 1.3" ask, not an oversight.
- The hybrid post-quantum groups are **preferred, not required** — a client without ML-KEM
  support (most things today) still connects fine over classical X25519/P-256; verified directly
  (a classical-only test client completed a TLS 1.3 handshake against the live server).
- `ttd_tls` was added to the backup/restore scripts (ADR-0006) so a restore doesn't force a fresh
  browser trust prompt on top of everything else — cheap to include, and `Postgres.DeleteAccount`
  taught the same lesson before: anything stateful that isn't backed up becomes a surprise later.
- **A second port-collision bug was found and fixed while wiring this up**, the same category as
  ADR-0006's `DeleteAccount` one: `verify-restore.sh`'s throwaway restore project reused the live
  stack's port *numbers* for the new HTTPS listeners (`docker-compose.yml`'s `PQC_TLS_APP_PORT`/
  `PQC_TLS_VERIFY_PORT` defaults), so a restore drill run while the real stack was up failed with
  "port is already allocated." Fixed by giving `restore.sh`'s throwaway project its own TLS port
  numbers too (`18543`/`18544`), the same way it already remapped the plain HTTP ports.

## Verification

Proven against the **live running container**, not just unit tests: `tls.Dial` against
`localhost:18443` shows TLS 1.3 (`0x0304`) and a negotiated `CurveID` of `4588`
(`X25519MLKEM768`) — the hybrid post-quantum group, actually chosen, not merely offered. A
second client restricted to classical curves completes the same handshake on `X25519` instead,
confirming graceful fallback. `curl` confirms `Strict-Transport-Security` is present on the
HTTPS response and absent on the HTTP one. New Go tests
(`ttd/server/internal/api/hsts_test.go`) cover the header logic (native TLS, behind-proxy header,
and plain HTTP) for both `Routes()` and `VerifyRoutes()`; full existing suite green on both
backends. The full `arsip.mjs` e2e suite (56 checks: uploads with a dropped connection and
resume, receipts, hybrid signatures, admin verification, offices, ledger linkage, CSP) re-run
against **both** `http://localhost:18099` and `https://localhost:18443` on the live Docker
stack — unchanged pass on both, proving the whole application works over the new HTTPS listener,
not only the TLS handshake in isolation. The backup/restore drill (ADR-0006) re-run after adding
`ttd_tls` and fixing the port collision — passes cleanly, zero containers/volumes left behind.
