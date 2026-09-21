# Threat model — browser client

Scope: the in-browser signer served at `/app/` (`ttd/web`). Everything about the server,
CA, formats and verifier is unchanged from upstream — see `security-findings.md` and the
upstream *Rencana V1* for those. This page covers only what changes when the signing key
lives in a browser instead of an OS keystore.

## Assets

| Asset | Where it lives |
|---|---|
| Device private key (ML-DSA-65 seed) | IndexedDB, only as `binding-key( Argon2id(PIN)+AES-GCM( key ) )`; plaintext only inside the wasm worker for one operation |
| PIN | typed into a `<dialog>`, passed to the worker, dropped after the operation; never stored |
| Access token | `sessionStorage` (per tab, cleared on close/logout) |
| Pinned Root CA | IndexedDB vault record (public data; its SHA-256 is displayed) |
| Document being signed | page memory; the original is sent to the server only for the QR stamp |

## Defences

- **Strict CSP** on `/app/*`: `script-src 'self' 'wasm-unsafe-eval'`, `style-src 'self'`,
  `connect-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`.
  The page has no inline script/style/handler, no third-party origin, no `eval`. Tests:
  `TestBrowserClientSourceIsCSPClean` (source), `TestWebAppIsServedUnderAStrictCSP`
  (headers), and the e2e asserts **zero** `securitypolicyviolation` events.
- **Key isolation.** The page (main thread) only ever sees the PIN-wrapped blob. Composite
  worker operations (`enroll`, `sign`, `checkPIN`, `certMatchesKey`) unwrap, use and zero the
  key inside the worker. The e2e records every worker→page message and asserts no plaintext
  key bytes cross it.
- **PIN envelope** (`core/webkeys`): Argon2id 64 MiB / t=3 / p=4, random salt, AES-256-GCM,
  AAD-bound format; KDF parameters read from storage are bounded before any work
  (a tampered vault cannot request a 4 GiB Argon2).
- **Device-binding key** (WebCrypto, non-extractable) — a copied IndexedDB file cannot be
  opened elsewhere; script on the page can *use* it but not read it.
- **Hostile PDF.** Parsing happens in the worker under a 60 s watchdog and the page
  terminates and respawns the worker on timeout (upstream SF-1). PDF.js runs with
  `isEvalSupported:false`.
- **Root CA pinning.** Trust on first use, then pinned; a changed root disables signing and
  shows a warning. Local verification uses only the pinned root, never a certificate
  supplied by the document.
- **Certificate ↔ key check** at activation and again before every signature.
- **Same-origin only**: no server-URL field (nothing to redirect to a look-alike host),
  no CORS.
- **No server signing path**: asserted by test.

## Threats and residual risk

| Threat | Status |
|---|---|
| XSS in the app origin | Mitigated by CSP + no inline code + escaped output, **not eliminated**: an attacker who executes script in `/app/` can wait for the user to enter the PIN and request a signature. The PIN-per-signature prompt limits this to interactive sessions; it does not stop a signature the attacker triggers while the dialog is being shown. |
| Browser extension / malicious browser profile | Out of scope: can read page memory and the PIN as typed. Same class as malware on a desktop. |
| Stolen laptop, IndexedDB copied off disk | Needs the PIN (Argon2id) **and** the binding key (bound to the browser profile). Weak PIN ⇒ offline guessing on the same profile; use a strong one. |
| Forgotten PIN / cleared site data | Key lost by design; report lost + re-enrol. |
| Plain-HTTP deployment | `crypto.subtle` is unavailable: the binding layer is absent (UI warns). The PIN envelope still holds. Traffic (token, PDFs) is readable on the network — **use HTTPS outside localhost**. |
| Malicious/compromised server serving altered JS | The page is only as trustworthy as the server that serves it (inherent to a web app; the desktop app is code-signed instead). Mitigations: `Cache-Control: no-cache` + ETag, CSP, the server has no key. A compromised server could still serve a client that exfiltrates keys — for that threat model use the native apps or subresource pinning. |
| Rogue CA / lab CA | The bundled CA is a **lab** CA; production needs the offline-root ceremony. |
| Device clock | Signing time is the client's claim, not a trusted timestamp (no TSA). |

## Explicit non-goals

Hardware-backed keys, multi-device roaming keys, TOTP for end users (admin only, as
upstream), and ledger anchoring (deferred).
