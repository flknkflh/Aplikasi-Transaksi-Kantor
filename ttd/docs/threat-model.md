# Threat model (summary)

Full text: Rencana V1 §5, §24, §26, §29. This is the working checklist.

## Guarantees targeted (§5.1)

* Server compromise does not yield user private keys.
* The server cannot forge a user signature (it has no key, no signing endpoint).
* Every signature traces to account + device + certificate + PDF.
* A PDF altered after signing fails verification.
* A lost device is revoked without disabling the user's other devices.

## Limits (§5.2)

* Malware on the device can attempt to use/steal the key while the app has it in memory.
* Rooted Android / admin Windows raises local-attack risk.
* Without a TSA, the client-written signing time has no independent proof.
* A QR on paper only opens the server record; it does not attest the whole page.
* A private Root CA is not automatically trusted by general PDF readers.

## Invariants enforced in code (§5.3)

| Invariant | Where |
|---|---|
| No private key in logs / requests / DB / images | `core` never logs key bytes; server rejects PKCS#8 uploads (M6) |
| Trust only the configured Root CA | `verification.VerifyPDF` requires `RootPEM`; `TrustSelfSigned` never set in prod path |
| Root inside the PDF is not an anchor | uses `digitorus/pdfsign` `TrustedRoots` only |
| One key per device | key generated on-device; no import path |
| Identity from account, not CSR subject | `enrollment.ParseAndValidateCSR` returns subject as info only; `labpki.IssueDeviceCert` takes subject from caller |
| PQC-only profile | `RequireMLDSAOnly` rejects non-ML-DSA signers |

## Negative tests (§25.4, §26)

Covered by `core/spike`: tampered PDF rejected, wrong Root CA rejected, CSR
with broken signature rejected, non-ML-DSA key rejected.

Covered by `tools/ca-admin/castore_test.go`: revoked cert rejected via a fresh
CRL; CSR subject cannot set the issued identity.

Covered by `server/internal/api/api_test.go`: submit of a tampered PDF, a
different device's certificate, a revoked certificate, or a mismatched
public-id all rejected (422); a revoked device cert blocks new reservations;
another account cannot read a signature record; `POST /api/v1/sign` and
`/users/{id}/sign` do not exist; enrollment / device-loss / admin routes are
403 without a TOTP-authorized session, and a plain login is refused once MFA
is confirmed; the login endpoint returns 429 under a burst.

Covered by M3 fuzzing (`core/**/fuzz_test.go`): `keys.ParsePKCS8`,
`enrollment.ParseAndValidateCSR`, `certutil.ParseCertificatePEM` /
`ParseChainPEM` / `ValidateCRL` survive millions of mutated inputs with no
panic and no false "valid" verdict. `verification.VerifyPDF` / `signing.SignPDF`
have a size cap + `recover` + `Options.Timeout`.

Known finding **SF-1** (`docs/security-findings.md`): a crafted PDF loops the
third-party parser (`github.com/digitorus/pdf`). Mitigated by the 15 s server
timeout + rate limits + 64 MiB cap; residual CPU risk until an upstream fix or
a subprocess sandbox lands.

Pending (M8): reserve/submit replay across restarts, symlink / path-traversal
on upload + export, account switch while a device key is open, CRL-cache-stale
warning surfaced in the client UI.
