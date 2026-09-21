# Release checklist

## Milestones (§23) and gate criteria

| ID | Deliverable | Passes when |
|---|---|---|
| M0 | Baseline + licences | `pdfsign` baseline tests pass; dependency lock committed; third-party notices written; GPL `pdfsigner` marked reference-only |
| M1 | ML-DSA spike cross-platform | one PDF signs + verifies on Windows amd64 **and** Android arm64; timings/size/memory recorded; corrupt PDF rejected |
| M2 | PKI lab | Root→Intermediate→device verifies; revoked cert rejected per policy |
| M3 | Core library | no UI deps; all golden + fuzz tests pass |
| M4 | Windows client | uninstall/reinstall, key loss, re-enrollment recovery all behave per policy; DPAPI wrapping verified |
| M5 | Android client | no key in logcat/network capture; sign+verify on ≥2 API levels |
| M6 | Receiver API | rejects corrupt PDF, wrong cert, revoked cert, user/device mismatch, transaction-id mismatch |
| M7 | CA admin + revocation | public server holds no Root/Intermediate private key |
| M8 | End-to-end | all §25 acceptance tests pass |
| M9 | Packaging + release | `.exe` + installer + `.apk` + server image from pipeline; SBOM + SHA256SUMS; backup/restore drill; tag `v1.0.0-lab` then `v1.0.0` |

## Current state

* **M0** done.
* **M1** done: `pqcsign-cli spike` green on Windows; debug APK runs the same
  spike on a physical arm64 device (keygen-on-device + sign + verify + tamper
  / wrong-root rejection). Left for full sign-off: a logcat/network capture
  proving no key leakage (§25.1).
* **M2** done: `tools/ca-admin` (`init/validate/issue/revoke/crl/show`) with
  the gate test — Root→Intermediate→device chain verifies, a revoked cert is
  rejected via a fresh ML-DSA-65 CRL, CA private keys stay out of any server.
* **M6 slice 1** done: `server/` receiver API — register/login (Argon2id +
  HS256 JWT), device + CSR registry, admin cert issuance (chain + CSR-key
  match), reservation, strict submit verification, public multipart verifier,
  audit log. `api_test.go` covers the §25.4 rejections (tampered PDF, wrong
  device cert, revoked cert, public-id mismatch, cross-account read) and
  asserts there is no signing endpoint.
* **M6 slice 2** done: `store.Postgres` behind an `api.Store` interface with
  embedded, `schema_migrations`-guarded migrations (`0001_init`, `0002_mfa`) —
  the **whole `api_test.go` suite passes against real PostgreSQL 16**.
  `store.NewS3Objects` (MinIO/S3) for signed blobs. **TOTP MFA** (RFC 6238,
  hand-rolled): `auth/mfa/setup` + `auth/mfa/verify`, `code` in login,
  enforced on enrollment / device-loss / all admin routes (§24). **Rate
  limiting** (`golang.org/x/time/rate`) on login / reserve / submit / verify.
  `deploy/lab/` Docker Compose (`compose config` validated), multi-stage
  Dockerfile, Caddyfile. Not run here: `docker compose up` + the API image
  build (this machine can't reach Docker Hub). Left: `auth/refresh` +
  token revocation, `admin/enrollments/{id}/approve|export`, backup/restore
  drill.
* **M3 core hardening** done: Go native fuzz tests for every
  attacker-controlled parser (`keys.ParsePKCS8`, `enrollment.ParseAndValidateCSR`,
  `certutil.ParseCertificatePEM`/`ParseChainPEM`/`ValidateCRL`,
  `verification.VerifyPDF`/`ListPDFSignatures`, `signing.SignPDF`). The stdlib
  `crypto/x509`-backed ones survive millions of execs with no panic (CI fuzzes
  them 20–30 s each). `VerifyPDF`/`SignPDF` gained a size cap (`MaxPDFBytes`
  64 MiB), a `recover` guard, and an `Options.Timeout` (server: 15 s). Fuzzing
  found **SF-1** — a CPU-loop DoS in `github.com/digitorus/pdf` on crafted
  input; mitigated (timeout + rate limits + size cap) and tracked in
  `docs/security-findings.md` with an upstream-report / sandbox TODO. Golden
  test pins the CMS shape (SubFilter, SHA-512, ML-DSA-65). `staticcheck` and
  `govulncheck` clean (one transitive advisory, `x/crypto/openpgp`, not
  reachable from our code).
* **M4 Windows client** mostly done: `apps/windows/internal/keystore` — DPAPI
  key protection (§12.1: PKCS#8 → AES-256-GCM → random wrapping key →
  Argon2id(PIN) → DPAPI CurrentUser), tested on Windows for round-trip, tamper,
  wrong-PIN, and a corrupted/foreign blob failing to open (§26).
  `internal/apiclient` (typed §17 client), `internal/appcore` (the seven §20
  pages as GUI-independent Go). `appcore_windows_test.go` runs the full flow —
  login → keygen+DPAPI → enroll → offline cert issuance → cert active →
  sign (local verify + submit) → verify → history → wrong-PIN rejected →
  reset — against a fake receiver that checks with the real `core/verification`.
  `cmd/pqcsign-desktop` is the Wails v2 shell + a plain-HTML frontend, one
  page per screen; it compiles (`go build`) — `wails build` + UI polish is a
  later slice. Server gained `admin/enrollments/{id}/export` + `/approve`.
* **M5 Android client** mostly done: `core/KeyVault.kt` — Android Keystore
  AES-256-GCM wrapping key (StrongBox→TEE→software fallback,
  `setUnlockedDeviceRequired`, 30 s auth window), ML-DSA PKCS#8 encrypted in
  internal storage, excluded from Auto Backup; `securityLevel()` reports
  TEE/StrongBox (§12.2). `net/ApiClient.kt` (OkHttp, §17), `app/AppCore.kt`
  (the §21 pages as GUI-independent Kotlin, mirrors Windows appcore),
  `app/AppState.kt`. `MainActivity` is a 9-screen plain-Views shell with SAF
  pick/save + `BiometricPrompt` before signing + a Diagnostics screen running
  the M1 spike. `ApiClientTest` (7 JVM tests, MockWebServer) green;
  `KeyVaultInstrumentedTest` (round-trip, tamper, security-level) is an
  androidTest — needs a device/emulator. Debug APK builds (~25 MB). Compose
  migration + in-app QR scanner + on-device run are a later slice.
* **M7 production PKI** done: `tools/ca-admin` gains encrypted CA keys
  (`PQC_CA_PASSPHRASE` → Argon2id + AES-256-GCM `key.pem.enc`), an append-only
  checksummed `ceremony.jsonl` (operator + per-artifact SHA-256 + encryption
  posture), `batch-issue` (a directory of CSRs + `.meta.json`), `crl` with RFC
  5280 reason codes, `status` + `backup`/`restore` that run the **M7 gate**
  (`public/` holds no private-key material). `docs/pki-ceremony.md` is the full
  witnessed air-gapped runbook (init → back up → distribute public only →
  batch-issue → revoke/CRL → rotation). Tests: `m7_test.go` (encrypted
  round-trip, wrong passphrase, ceremony-log checksums, gate, backup/restore
  keeps original, CRL reason code). Manual run verified end to end (issue →
  sign → verify valid → revoke → CRL → verify revoked → backup → restore).
  Open post-V1: PKCS#11/HSM, signed enrollment-package format.
* **M8 acceptance** done: `docs/acceptance-v1.md` maps every §25 item to its
  check; gap tests added (`server/internal/api/acceptance_test.go`,
  `core/mobilebridge/bridge_test.go`, `TestStaleCRLWarns`);
  `tools/acceptance.sh` runs the lot + the local e2e and prints a roll-up. The
  QR record now reflects a revoked certificate. Manual sign-offs remaining are
  listed in the doc (on-device KeyVault test, biometric cancel, `docker
  compose` bring-up + backup/restore drill, a real cross-platform PDF check).
* **M9 packaging** done: `.github/workflows/release.yml` (tag-triggered:
  Windows CLI + Wails `-nsis` installer + Authenticode; Android AAR +
  `assembleRelease` signed from secrets; server image → GHCR; SBOMs;
  `SHA256SUMS`; GitHub release). `tools/release-local.sh` builds everything
  buildable locally into `dist/release/` with CycloneDX SBOMs + checksums —
  verified: `pqcsign-cli`/`ca-admin`/`pqc-api` exes, the debug APK, 4 SBOMs,
  `SHA256SUMS.txt`, third-party notices. `apps/android` release signing reads
  `PQC_ANDROID_KEYSTORE*` from the environment (keystore never in the repo).
* **V1 code-complete.** Left before tagging `v1.0.0`: the manual sign-offs
  above, real signing keys wired into CI secrets, and the production PKI
  ceremony + VPS deploy (`docs/pki-ceremony.md`, §28).

## Per-release (M9)

* [ ] Windows build on a Windows runner; Authenticode signed if key available
* [ ] Android release APK signed with the release keystore
* [ ] Server multi-stage image; DB migrations from empty
* [ ] SBOM generated; `SHA256SUMS.txt` generated; artifacts signed
* [ ] Dependency + container + secret scans clean
* [ ] User + admin guides updated
* [ ] Backup/restore drill: PostgreSQL + MinIO restored, PDF hashes match
* [ ] All §25 acceptance boxes signed off by the test team
* [ ] CA / release / Authenticode keys are in CI secret storage, not the repo
