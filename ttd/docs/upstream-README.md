# PQC PDF Sign V1 — client-side signing

Post-quantum PDF signing with **ML-DSA-65** (FIPS 204), client-side only. The
private key is generated on the user's device, protected by the OS
(Windows DPAPI / Android Keystore), and **never sent to the server**. The
server receives already-signed PDFs, re-verifies them strictly, stores the
result, and serves a public verifier.

Full plan: `Rencana_Pembuatan_PQC_PDF_Sign_V1_Client_Side.md` (section numbers
below refer to it).

## Status

**All milestones M0–M9 done — V1 is code-complete.** Every component builds,
`go vet` / `gofmt` clean, and its tests pass; the full flow runs locally end
to end (`tests/e2e/local-run.sh`). Before tagging `v1.0.0`: the manual
on-device sign-offs in `docs/acceptance-v1.md`, real signing keys in CI
secrets, and the production PKI ceremony + VPS deploy (`docs/pki-ceremony.md`,
§28).

| Component | State |
|---|---|
| `core/` — keys, enrollment, signing, verification, CRL, mobilebridge | unit + fuzz + golden tests; `staticcheck`/`govulncheck` clean; SF-1 (parser DoS) mitigated |
| `apps/windows/` | `internal/{keystore(DPAPI),apiclient,appcore}` tested end to end; `cmd/pqcsign-desktop` (Wails) + `cmd/pqcsign-cli` |
| `apps/android/` | `KeyVault` (Android Keystore §12.2), OkHttp `ApiClient`, `AppCore` (§21), 9-screen UI + biometric + SAF; JVM tests green; debug APK builds |
| `server/` | all §17 routes, strict submit verification, TOTP MFA, rate limits; in-memory **or** PostgreSQL (embedded migrations; suite passes on real PG16) + MinIO blobs |
| `tools/ca-admin/` | offline CA CLI: encrypted keys, ceremony log, batch-issue, CRL reason codes, backup/restore, M7 gate |
| `deploy/lab/` | Docker Compose (caddy+api+postgres+minio) + multi-stage Dockerfile + Caddyfile (`compose config` validated) |
| CI / release | `.github/workflows/ci.yml` (fmt, vet, tests, PG suite, AAR, APK, Windows client, fuzz smoke, local e2e); `release.yml` (tag → signed artifacts + SBOMs + image + GitHub release) |

Local packaging: `bash tools/release-local.sh` → `dist/release/` (exes, debug
APK, CycloneDX SBOMs, `SHA256SUMS.txt`).

## Crypto profile (§4)

* Signature: ML-DSA-65, CMS pure mode (RFC 9882)
* Digest: SHA-512
* PDF: PAdES Baseline-B (`PAdES_B`)
* Trust: explicit Root CA only — a root embedded in a PDF is never an anchor (§5.3)
* Timestamp: not in V1 (client-claimed time is shown but not trusted)

## Layout

```
core/            framework-independent Go: keys, enrollment, signing, verification, mobilebridge
  keys/          ML-DSA-65 generation + PKCS#8 (de)serialisation
  enrollment/    device CSR creation + server-side CSR validation
  signing/       PAdES-B ML-DSA-65 signing + visible appearance + QR
  verification/  verify against explicit Root CA (+ offline CRL); shared JSON result (§11.3)
  certutil/      X.509 / CRL parsing and profile checks
  labpki/        LAB-ONLY throwaway Root/Intermediate CA + device cert + CRL
  spike/         the M1 end-to-end proof, callable from any platform
  **/fuzz_test.go  Go native fuzzing of every attacker-controlled parser (M3)
apps/windows/    internal/{keystore(DPAPI),apiclient,appcore}; cmd/pqcsign-desktop (Wails), cmd/pqcsign-cli (M1)
apps/android/    Kotlin client: core/KeyVault + net/ApiClient + app/AppCore; MainActivity 9-screen shell
server/          Receiver API — internal/{store,auth,api}; strict submit verify + public verifier
tools/ca-admin/  offline CA CLI: init / validate / issue / batch-issue / revoke / crl / status / backup / restore / show
pki/             CA templates, scripts, published public material
deploy/          lab (Compose) and production recipes
docs/            architecture, api, pki-ceremony, threat-model, release-checklist
research/        notes only — reference repos are cloned here, never vendored
```

## Quick start (M1 spike)

Requires Go 1.27.

```sh
# from repo root
cd apps/windows
go build -o ../../dist/pqcsign-cli.exe ./cmd/pqcsign-cli

cd ../..
./dist/pqcsign-cli.exe spike --out dist/spike-out
```

The spike builds a lab ML-DSA-65 PKI, enrolls a device, signs the bundled
sample PDF, verifies it against the explicit Root CA, and proves that a
tampered PDF and an unrelated Root CA are both rejected. Artifacts and
`report.json` (timings, sizes, memory) land in `dist/spike-out/`.

Other subcommands: `genpki`, `keygen`, `pubkey`, `csr`, `sign`, `verify`,
`version` — run `pqcsign-cli <cmd> -h`.

```sh
# sign an arbitrary PDF with lab material, then verify it standalone
./dist/pqcsign-cli.exe genpki --out dist/lab-pki
./dist/pqcsign-cli.exe sign   --in mydoc.pdf --key dist/lab-pki/device-key.pkcs8.pem \
                              --chain dist/lab-pki/ca-chain.pem --out mydoc.signed.pdf \
                              --signer "Nama Pengguna" --public-id sig_demo --qr
./dist/pqcsign-cli.exe verify --in mydoc.signed.pdf --root dist/lab-pki/root-ca.crt.pem \
                              --intermediate dist/lab-pki/intermediate-ca.crt.pem \
                              --crl dist/lab-pki/crl.pem
```

## Tests

```sh
cd core && go test ./...
```

`core/spike` runs the automated M1 acceptance checks (§25.3–§25.5).

## Licensing (§3, §9.3)

Built on `github.com/digitorus/pdfsign` (BSD-2-Clause), pinned to the baseline
commit `39f87fec…` / `v1.0.0-rc2`. `digitorus/pdfsigner` (GPLv3) is studied as
a reference only and is **not** a dependency. See
`LICENSES/THIRD_PARTY_NOTICES.md`.

Module paths use the `example.internal/` placeholder — replace with the real
organisation domain before any release.

## Security invariants (§5.3)

* No private key in source, logs, DB, HTTP requests, telemetry, crash reports, or images.
* The server has **no** endpoint that signs a PDF on a user's behalf.
* One key per device; never copied between devices.
* All trust decisions use the configured Root CA, not a root carried in the PDF.
* Certificate identity comes from the verified account, not from the CSR subject.
