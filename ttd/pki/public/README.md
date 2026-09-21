# pki/public/

Published, non-secret trust material only:

* `root-ca.crt.pem` — the trust anchor shipped inside every client and verifier
* `ca-chain.pem` — Root + Intermediate certificates
* `crl.pem` — latest CRL

Populated by the CA admin process (M7) and served at `/api/v1/public/ca/*`.
Never place a private key here.
