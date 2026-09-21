# tools/ca-admin

Offline CA operator for PQC PDF Sign V1 (Rencana V1 §13, §14, §17.5). Runs on
the air-gapped admin machine — never on a server.

```sh
cd tools/ca-admin && go build -o ../../dist/ca-admin .

# --- lab (plaintext keys) ---
ca-admin init     --dir ./ca
ca-admin validate --csr device.csr.pem
ca-admin issue    --dir ./ca --csr device.csr.pem \
                  --account acct_42 --device "Windows Laptop" --cn "Nama Pengguna"
ca-admin revoke   --dir ./ca --serial <hex> --reason keyCompromise
ca-admin crl      --dir ./ca
ca-admin status   --dir ./ca        # fingerprints + the M7 gate
ca-admin show     --in ./ca/public/crl.pem

# --- production (encrypted keys + ceremony log) ---
export PQC_CA_PASSPHRASE='…strong passphrase…'
export PQC_CA_OPERATOR='name@org'
ca-admin init        --dir /mnt/ca/pqc-ca            # writes key.pem.enc
ca-admin batch-issue --dir /mnt/ca/pqc-ca --in /media/in --out /media/out
ca-admin backup      --dir /mnt/ca/pqc-ca --out /mnt/backup-A/pqc-ca.tar.gz
ca-admin restore     --in  /mnt/backup-A/pqc-ca.tar.gz --dir /tmp/drill
```

Full runbook: `docs/pki-ceremony.md`.

## CA directory layout

```
ca/
  root/{key.pem | key.pem.enc}  root/cert.pem      # Root CA (offline)
  intermediate/{key.pem | key.pem.enc}  intermediate/cert.pem
  public/  root-ca.crt.pem  intermediate-ca.crt.pem  ca-chain.pem  crl.pem
  ledger.json    { crl_number, revocations[] with RFC 5280 reason codes }
  issued.jsonl   one JSON line per issued device certificate
  ceremony.jsonl append-only audit: operator, encryption posture, SHA-256 of
                 every artifact touched
```

Only `public/` is ever copied to a server (§28). `init` refuses an existing
directory; `restore` refuses to overwrite one and re-checks the gate.

## Guarantees (tested — `castore_test.go`, `m7_test.go`)

* Identity is `--cn`/`--org` (or `.meta.json`), **never** the CSR subject (§13.5).
* CSR proof-of-possession + ML-DSA-65 enforced.
* Issued device certs: `keyUsage=digitalSignature`, id-kp-documentSigning EKU, `CA:FALSE`.
* `PQC_CA_PASSPHRASE` set → keys stored Argon2id + AES-256-GCM; wrong passphrase fails; no-passphrase open refused.
* `crl` re-signs a fresh ML-DSA-65 CRL with a monotonic number and reason codes.
* `ceremony.jsonl` lines carry a SHA-256 for each artifact and the encryption posture.
* **M7 gate**: `status` / `restore` fail if `public/` holds any private-key material.
* `backup` → `restore` produces an independent, usable CA and leaves the original untouched.

## Still open (post-V1)

PKCS#11 / HSM backing for the CA key, a signed enrollment-package format
(instead of a bare CSR directory), Shamir-split passphrase custody helpers.
