# Acceptance — Rencana V1 §25

Every §25 checkbox and where it is verified. `A` = automated (test / script),
`M` = manual on-device step still required. Run everything with:

```sh
tools/acceptance.sh          # all module tests + fuzz smoke + the local e2e run
```

## 25.1 — Key custody

| # | Item | How | Status |
|---|---|---|---|
| 1 | Windows key created locally + DPAPI-protected | `apps/windows/internal/keystore` `TestProtectUnprotectRoundTrip`, `appcore` `TestClientEndToEnd` | A |
| 2 | Android key created locally + Keystore-wrapped | `apps/android` `KeyVaultInstrumentedTest` (device) | A (M: run on device) |
| 3 | No user private key on server filesystem | server never writes keys; `store` has no key column | A (by construction) |
| 4 | No user private key in the database | idem; `TestAcceptance_NoPrivateKeyAnywhere` scans responses | A |
| 5 | No private key in enrolment / submission network capture | client sends CSR + signed PDF only; `bridge`/`appcore` tests | A |
| 6 | No private key in logs / crash reports | `server` audit never logs key bytes; `TestAcceptance_NoPrivateKeyAnywhere` (audit-events) | A |
| 7 | Server has no signing endpoint | `api_test` `TestNoSigningEndpoint` | A |

## 25.2 — Enrollment

| # | Item | How | Status |
|---|---|---|---|
| 1 | Valid CSR accepted | `api_test` `TestHappyPath`; `ca-admin` `TestOfflineIssuanceAndRevocation` | A |
| 2 | CSR with a broken signature rejected | `enrollment` `TestValidateCSRRejectsTamperedSignature`; `core/enrollment/fuzz_test.go` | A |
| 3 | Non-ML-DSA-65 CSR rejected (PQC-only) | `enrollment` `ParseAndValidateCSR` + `TestCreateDeviceCSRRejectsNonMLDSAKey` | A |
| 4 | CSR subject cannot set the identity | `ca-admin` issue uses `--cn`; `TestOfflineIssuanceAndRevocation` asserts CN ≠ CSR subject | A |
| 5 | Cert not matching the on-device key rejected by client | `appcore` `CertificateStatus` (`keys.SameKeyPair`); Android `AppCore` verifies at sign time | A |
| 6 | One account, separate Windows + Android certs | `TestAcceptance_DeviceLossIsolation` (two devices, two certs) | A |

## 25.3 — Signing (client)

| # | Item | How | Status |
|---|---|---|---|
| 1 | Signed locally without uploading the original | `appcore.SignPDF` / Android `AppCore.signPdf` read the PDF locally; only `reserve` (hash) + `PUT document` (signed) hit the network | A |
| 2 | Output carries the certificate chain + appearance | `signing` `TestGoldenCMSStructure`; `core/spike` | A |
| 3 | QR / public_id inside the signed area | `signing.SignPDF` puts `public_id` in the appearance + CMS `Contact`; server checks `PublicID()` matches | A |
| 4 | Client verifies before upload | `appcore.SignPDF` runs `verification.VerifyPDF` and aborts on failure; Android `AppCore.signPdf` `require(local.valid)` | A |
| 5 | Cancelled if PIN / biometric fails | Windows: `keystore` auth-bound; Android: `KeyVault` 30 s auth window + `BiometricPrompt`; `TestWrongPINRejected`, `appcore` wrong-PIN case | A (M: biometric UX on device) |
| 6 | Encryption nonce not reused | `keystore` `TestProtectUnprotectRoundTrip` (blob differs each write); `KeyVaultInstrumentedTest` | A |

## 25.4 — Server submission

| # | Item | How | Status |
|---|---|---|---|
| 1 | Valid PDF accepted + stored | `api_test` `TestHappyPath` | A |
| 2 | One byte changed → rejected | `api_test` `TestSubmissionRejections/tampered_PDF`; `core/spike` | A |
| 3 | Wrong Root → rejected | `core/spike` `wrong_root_rejected`; `verification` `TestMalformedNeverPanics` | A |
| 4 | Wrong Intermediate → rejected | server verifies full chain to the configured Root; `TestSubmissionRejections` | A |
| 5 | Certificate of another account → rejected | `TestAcceptance_DifferentAccountCertificate` | A |
| 6 | Certificate of another device → rejected | `api_test` `TestSubmissionRejections/certificate_of_a_different_device` | A |
| 7 | Revoked certificate → not accepted for new signatures | `TestSubmissionRejections/revoked_certificate`; `ca-admin` gate | A |
| 8 | public_id mismatch → rejected | `TestSubmissionRejections/public_id_mismatch` | A |
| 9 | Resubmission is idempotent | `api_test` `TestHappyPath` (second PUT → 200) | A |

## 25.5 — Verification

| # | Item | How | Status |
|---|---|---|---|
| 1 | Windows verifies an Android-signed PDF | `core/mobilebridge` `TestBridgeSignVerifiesEverywhere` (bridge-signed → `verification.VerifyPDF`) | A |
| 2 | Android verifies a Windows-signed PDF | idem — one `core` engine on both platforms; bridge `VerifyPDF` agrees | A |
| 3 | Server produces a consistent result | `api_test` `TestHappyPath` public `/verify` returns the shared JSON | A |
| 4 | Verifier does not trust a root embedded in the PDF | `verification.VerifyPDF` uses `TrustedRoots` only; `core/spike` wrong-root | A |
| 5 | Client vs server time distinguished | `TestAcceptance_ClientTimeVsServerTime` | A |
| 6 | Warn on a stale CRL cache | `verification` `TestStaleCRLWarns` | A |
| 7 | QR record offers upload for full verification | `publicRecord` note + `POST /api/v1/verify`; `docs/api.md` | A |

## 25.6 — Revocation and device loss

| # | Item | How | Status |
|---|---|---|---|
| 1 | Revoking Android does not revoke the account's Windows cert | `TestAcceptance_DeviceLossIsolation` | A |
| 2 | A revoked device cannot make a new reservation / submission | `TestAcceptance_DeviceLossIsolation`; `TestSubmissionRejections/revoked_certificate` | A |
| 3 | Historic signature stays readable with a clear revocation status | `TestAcceptance_DeviceLossIsolation` (public record → `certificate_status: revoked`) | A |
| 4 | Re-enrolment makes a new key and a new serial | `TestAcceptance_ReEnrolFreshKeyAndSerial` | A |

## 25.7 — Operational

| # | Item | How | Status |
|---|---|---|---|
| 1 | Restart of all containers keeps data | `store.Postgres` (durable); compose named volumes | A (M: `docker compose` bring-up) |
| 2 | PostgreSQL backup restores | standard `pg_dump`/`pg_restore`; `deploy/lab/README.md` | M |
| 3 | MinIO backup restores | `mc mirror`; `deploy/lab/README.md` | M |
| 4 | PDF hash identical after restore | object bytes are immutable; `signed_pdf_sha512` recorded | A (by design) |
| 5 | Migration runs from an empty database | `store` `applyMigrations`; `server-postgres` CI job (fresh PG each run) | A |
| 6 | Server re-installable from image + a new `.env` | `deploy/lab/Dockerfile` + `.env.lab.example`; `docs/pki-ceremony.md` §3 | A (M: image build) |

## Manual sign-off still required

* `KeyVaultInstrumentedTest` on a physical arm64 device (25.1 #2, 25.5).
* On-device biometric cancellation (25.3 #5).
* `docker compose up` bring-up + Postgres/MinIO backup–restore drill (25.7 #1–3, #6).
* Cross-check a real PDF: sign on Windows → verify on Android and vice versa,
  then upload to the public verifier (25.5).
