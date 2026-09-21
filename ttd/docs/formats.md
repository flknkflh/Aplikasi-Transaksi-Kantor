# Frozen formats (§31 step 5)

These interfaces must stay stable across UI-framework choices. Code is the
source of truth; this file is the summary and the change log.

## 1. Key blob

* In memory / on the wire between `core` and the platform layer: **PKCS#8**,
  unencrypted, DER or a single `PRIVATE KEY` PEM block.
* Algorithm: **ML-DSA-65 only**. `keys.ParsePKCS8` rejects anything else.
* For ML-DSA-65 the PKCS#8 payload is the 32-byte FIPS 204 seed, so a PEM key
  file is ~128 bytes — this is expected, not a truncated key.
* The platform layer wraps this blob immediately (Windows DPAPI `CurrentUser`
  / Android Keystore AES) and never persists or transmits it (§5.3, §12).
* Public half: PKIX `SubjectPublicKeyInfo`, `PUBLIC KEY` PEM.

## 2. CSR

* PKCS#10, `CERTIFICATE REQUEST` PEM, self-signed with the device key
  (proof of possession).
* Public key algorithm ML-DSA-65.
* `enrollment.Request` JSON (the gomobile form) — only `common_name`,
  `organization`, `organizational_unit` reach the PKCS#10 subject; the rest
  (`account_label`, `device_label`, `platform`) are enrollment metadata.
* The server / CA **ignores the CSR subject** as an identity source (§13.5).

## 3. Device certificate

X.509 v3, signed ML-DSA-65 by the Intermediate CA:

| field | value |
|---|---|
| subject | assigned by the CA operator from the verified account |
| serial | random 128-bit |
| public key | ML-DSA-65 (from the CSR) |
| `basicConstraints` | `CA:FALSE` |
| `keyUsage` | `digitalSignature` |
| EKU | `1.3.6.1.5.5.7.3.36` (id-kp-documentSigning) — **required**; `digitorus/pdfsign` verify rejects a signer without it |
| validity | limited (V1 default 365 d) |
| CRL DP | Intermediate CRL URL, if online revocation is used |

Implemented by `labpki.IssueDeviceCert`; checked by
`certutil.ParseAndValidateCertificate`.

## 4. Signature on the PDF

* **PAdES Baseline-B** (`pdfsign.PAdES_B`), SubFilter `ETSI.CAdES.detached`.
* CMS: pure ML-DSA-65 (RFC 9882), digest **SHA-512**, AlgorithmIdentifier
  parameters absent, `EncryptedDigest` length = ML-DSA-65 signature size.
* Certificate chain (leaf + intermediates) embedded in the CMS.
* No CMS signing-time attribute; no timestamp in V1.
* `public_id` binding: in the visible appearance text **and** a CMS `Contact`
  attribute (`pqc-public-id:<id>`), both inside the signed byte range.
  Binding into PDF `/Info` is a later step.
* Visible appearance: signer identity, `Algoritma: ML-DSA-65`, certificate
  serial, `Waktu (klaim klien)` (untrusted client time), reason, `ID
  verifikasi`, and a QR of the verification URL (or the `public_id`).

## 5. Verification result JSON (§11.3, §16.2)

Produced by `core/verification` (`verification.Result`) and used identically
by the Windows client, the Android client, and the server verifier:

```json
{
  "valid": true,
  "document_sha512": "...",
  "signatures": [
    {
      "valid": true,
      "algorithm": "ML-DSA-65",
      "certificate_serial": "...",
      "certificate_fingerprint": "...",
      "subject": "...",
      "trusted_chain": true,
      "revoked": false,
      "client_claimed_signing_time": "...",
      "timestamp_valid": false,
      "warnings": []
    }
  ]
}
```

Rules: trust anchor is the **explicitly supplied Root CA** only; a root inside
the PDF is never an anchor; `RequireMLDSAOnly` rejects non-ML-DSA signers;
offline CRL is checked separately by `core` and folded into `revoked` /
`warnings`. The server response adds `registered`, `signer_name`,
`device_label`, `certificate_status`, `server_received_at`.

## 6. CRL

`X509 CRL` PEM, signed ML-DSA-65 by the Intermediate CA, monotonically
increasing `Number`, `NextUpdate` set. `certutil.ValidateCRL` verifies the
issuer signature, checks freshness (`stale` past `NextUpdate`), and looks up
the signer serial.

## 7. API

Endpoint list: `docs/api.md` (from §17). Forbidden: any endpoint that signs a
PDF for a user (`POST /api/v1/sign`, `POST /api/v1/users/{id}/sign`).

## Change log

| date | change |
|---|---|
| 2026-09-02 | Initial freeze at M1/M2: items 1–7 as above. |
| 2026-09-02 | M3: `verification.SignatureResult` gains `reason` + `contact`; `VerifyPDF`/`SignPDF` gain `MaxPDFBytes` (64 MiB) and `Options.Timeout`. Wire shape unchanged; golden test in `core/signing/golden_test.go`. |
