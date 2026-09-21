# ADR-0002: Digital signature (TTD) as a browser client of the PQC PDF Sign mechanism

**Status:** Accepted (2026-09-21)
**Context:** the office needs digital signatures on PDF documents. The owner's own
project, *PQC PDF Sign V1* (`flknkflh/TTD_ELEKTRONIK`), already defines a complete,
tested mechanism; the request was to reuse **exactly that mechanism and architecture**,
but reachable from a **browser** instead of a Windows/Android application.

## Decision

1. **Import the mechanism unchanged** into `ttd/` (pinned upstream commit in
   [ttd/PROVENANCE.md](../../ttd/PROVENANCE.md)): `core` (ML-DSA-65 keys, CSR, PAdES
   Baseline-B signing, strict verification), `server` (accounts, devices, reservations,
   server-side QR stamp, strict re-verify on submit, public verifier, CRL, audit),
   `tools/ca-admin` (CA). The frozen interfaces (`ttd/docs/formats.md`,
   `ttd/docs/api.md`) are **not changed**; module paths stay
   `example.internal/pqc-pdf-sign/*`. All upstream tests pass in this repo.
2. **The only new component is the client.** The Go `core` is compiled to WebAssembly
   (`GOOS=js GOARCH=wasm`, no cgo — possible because ML-DSA is in Go's standard
   library) and runs in a Web Worker; the desktop UI is ported to plain HTML/JS
   (`ttd/web/src`). It is served by the existing API server, same origin, under `/app/`.
3. **Invariants kept from upstream and enforced by tests:**
   - the private key is generated on the user's device and never sent anywhere;
   - the server has **no endpoint that signs** (`POST /api/v1/sign` is 404 — asserted in
     Go and in the browser e2e);
   - only an explicit Root CA is trusted (pinned on first use, shown as a fingerprint,
     a later change disables signing);
   - identity comes from the account, not the CSR subject; one document = one signature;
   - the server re-verifies every submission strictly before accepting it.
4. **PIN is mandatory** (min. 6 characters). The key is stored as
   `Argon2id(PIN, 64 MiB, t=3) → AES-256-GCM` (`core/webkeys`, bounded KDF parameters
   on parse), then, when WebCrypto is available (HTTPS or `localhost`), sealed again with
   a **non-extractable** AES-GCM *device-binding key* held in IndexedDB. That second
   layer plays the role DPAPI / Android Keystore play on the other clients.
5. **Anchoring signed-PDF hashes to the Fabric ledger is deferred** ("TTD first").
   The natural hook is the existing outbox in `api/`; nothing in `ttd/` blocks it.
6. **Fixed by a separate commit, same day:** the ledger's `crypto` module moved from
   liboqs to Go's `crypto/mldsa` (see the addendum in ADR-0001), which is what makes (2)
   possible at all.

## Why not the alternatives

| Alternative | Rejected because |
|---|---|
| Server signs with a per-user key | Breaks the central promise (key never leaves the device; server cannot forge). |
| Re-implement signing in JavaScript | A second implementation of PAdES/CMS/ML-DSA to keep in sync with the verifier; the Go core is already tested and is what the server verifies with. |
| WebAuthn / passkeys as the signer | No ML-DSA support in authenticators; would not produce the PQC signature the verifier requires. |
| Keep the desktop/Android apps too | Out of scope by request ("gausah app/exe"); the upstream repo still has them. |

## Consequences

- **Cost:** `pqcsign.wasm` is ≈ 15 MB raw, ≈ 3.9 MB gzip (served pre-compressed, cached by
  ETag). Argon2id ≈ 0.2 s and signing ≈ 20 ms in Node; first-load time is dominated by the
  download.
- **Weaker than an OS keystore:** a browser cannot hold the key in hardware. Protection is
  the PIN envelope + binding key + strict CSP + a worker that only holds the key for one
  operation. See [ttd/docs/threat-model-browser.md](../../ttd/docs/threat-model-browser.md).
- **Clearing site data destroys the key.** Recovery is the upstream flow: report the device
  lost (admin revokes the certificate) and enrol a new key.
- **Lab PKI.** The CA is the upstream *lab* CA (online, auto-issuing) — fine for this spike,
  **not** a production trust anchor; production needs the offline-root ceremony in
  `ttd/docs/pki-ceremony.md` and a trusted timestamp (TSA), which V1 also lacks.
- **Signing time is the device clock**, not a trusted timestamp (upstream limitation, shown
  in the UI).

## Verification

`GOWORK=off go test ./...` in `ttd/core`, `ttd/server`, `ttd/tools/ca-admin`;
`node --test web/test/wasm.test.mjs` (real wasm under Node); and
`ttd/web/e2e` (real Chrome against a real server, 49 checks including CSP-violation,
network-content and worker-boundary assertions).
