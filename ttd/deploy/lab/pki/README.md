# deploy/lab/pki/

Mounted read-only into the `api` container at `/pki`. Drop the **public**
trust material here — never a private key.

```
root-ca.crt.pem     ca-chain.pem     crl.pem
```

Produce them with `tools/ca-admin`:

```sh
../../dist/ca-admin init --dir ../ca          # creates ../ca/ (git-ignored)
cp ../ca/public/root-ca.crt.pem        ./root-ca.crt.pem
cp ../ca/public/ca-chain.pem           ./ca-chain.pem
cp ../ca/public/crl.pem                ./crl.pem     # after `ca-admin crl`
```

`crl.pem` is optional at first boot; refresh it and restart `api` (or call
`POST /api/v1/admin/crl/import`) after each revocation.
