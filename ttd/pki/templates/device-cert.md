# Device certificate template (§13.4)

The CA issues one certificate per device. Identity is assigned from the
verified account — the CSR subject is advisory only.

| Field | Value |
|---|---|
| Version | v3 |
| Signature | ML-DSA-65 (from the Intermediate CA key) |
| Serial | random 128-bit, unique |
| Subject | assigned by CA from the account (`CN`, `O`; no excess PII) |
| Public key | ML-DSA-65, taken from the CSR |
| `basicConstraints` | `critical, CA:FALSE` |
| `keyUsage` | `critical, digitalSignature` |
| Extended key usage | `1.3.6.1.5.5.7.3.36` (id-kp-documentSigning) — **required by the verifier** |
| `subjectKeyIdentifier` | hash |
| `authorityKeyIdentifier` | keyid of the Intermediate |
| `crlDistributionPoints` | Intermediate CRL URL (if online revocation is used) |
| Validity | limited (V1 default: 365 days) |

`core/labpki.IssueDeviceCert` and `core/certutil.ParseAndValidateCertificate`
implement and check this profile.
