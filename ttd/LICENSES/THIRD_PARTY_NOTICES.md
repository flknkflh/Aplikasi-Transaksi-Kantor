# Third-party notices

PQC PDF Sign V1 redistributes and/or depends on the following components.

## digitorus/pdfsign — BSD-2-Clause  (dependency)

* Repository: <https://github.com/digitorus/pdfsign>
* Pinned baseline: commit `39f87fec7e33af3e3daa77f6fa86820b813036d5`
  (published as module version `v1.0.0-rc2`)
* Role: the shared PDF + cryptography engine (CMS, X.509, PAdES, appearance,
  CRL/OCSP) and the ML-DSA-44/65/87 signing and verification paths.
* Full licence text: `LICENSES/BSD-2-Clause-pdfsign.txt`.

Test fixtures `core/testpdf/sample.pdf` and `core/testpdf/sample-multipage.pdf`
are unmodified copies of `testfiles/testfile12.pdf` and `testfiles/testfile14.pdf`
from that repository, redistributed under the same BSD-2-Clause licence.

Transitive dependencies pulled in by `digitorus/pdfsign` (see `core/go.sum`):
`digitorus/pdf`, `digitorus/pkcs7`, `digitorus/timestamp`,
`mattetti/filebuffer`, `golang.org/x/crypto`, `golang.org/x/image`,
`golang.org/x/text` — each under its own permissive (BSD/MIT-style) licence.

## skip2/go-qrcode — MIT  (dependency)

* Repository: <https://github.com/skip2/go-qrcode>
* Role: renders the QR code embedded in the signature appearance (§16.3).

## Other Go dependencies

Generated SBOMs (`sbom-*.cdx.json`, CycloneDX) accompany every release and are
the authoritative dependency + licence inventory. Direct dependencies by
module:

| Module | Dependency | Licence | Role |
|---|---|---|---|
| server | `github.com/jackc/pgx/v5` | MIT | PostgreSQL driver |
| server | `github.com/minio/minio-go/v7` | Apache-2.0 | S3/MinIO object storage client |
| server | `golang.org/x/image` | BSD-3-Clause | opentype text rendering for the e-signature stamp caption |
| server | `golang.org/x/crypto` | BSD-3-Clause | Argon2id password hashing |
| server | `golang.org/x/time` | BSD-3-Clause | rate limiter |
| apps/windows | `github.com/wailsapp/wails/v2` | MIT | desktop GUI shell |
| apps/windows | `golang.org/x/sys` | BSD-3-Clause | Windows DPAPI (`CryptProtectData`) |
| apps/windows | `golang.org/x/crypto` | BSD-3-Clause | Argon2id (PIN-wrapped key) |
| core (tool) | `golang.org/x/mobile` (`gobind`) | BSD-3-Clause | Android AAR generation |

## Vendored browser assets

| File | Project | Licence | Role |
|---|---|---|---|
| `apps/windows/cmd/pqcsign-desktop/frontend/dist/vendor/pdf.min.js`, `pdf.worker.min.js` | Mozilla pdf.js 3.11.174 | Apache-2.0 | render a PDF page in the desktop app so the signer can drag the QR box onto it (vendored, offline; no CDN at runtime) |

## Android app dependencies (`apps/android/app/build.gradle.kts`)

| Dependency | Licence | Role |
|---|---|---|
| `androidx.appcompat`, `androidx.activity` | Apache-2.0 | Activity + Storage Access Framework |
| `androidx.biometric` | Apache-2.0 | biometric / device-credential prompt |
| `com.squareup.okhttp3:okhttp` (+ `mockwebserver`, test) | Apache-2.0 | HTTP client for the receiver API |
| `junit:junit`, `org.json:json`, `androidx.test:*` (test) | EPL-1.0 / Android-SDK / Apache-2.0 | unit + instrumented tests |

## digitorus/pdfsigner — GPLv3 or commercial  (NOT a dependency)

* Repository: <https://github.com/digitorus/pdfsigner>
* Reviewed commit: `54fd26fee2ff9799e3d07410a9a244075bdc4328`
* Role: **reference only.** Its REST/queue/verification patterns were studied
  while designing `server/`. No source from `pdfsigner` is copied into this
  product, and it is not imported by any module here. The V1 receiver is
  written fresh on top of the BSD `pdfsign` library so licensing and code
  responsibility stay unambiguous (Rencana V1 §3.2).

## Standards referenced

* NIST FIPS 204 — ML-DSA: <https://csrc.nist.gov/pubs/fips/204/final>
* RFC 9881 — ML-DSA in X.509: <https://www.rfc-editor.org/rfc/rfc9881.html>
* RFC 9882 — ML-DSA in CMS: <https://www.rfc-editor.org/rfc/rfc9882.html>
