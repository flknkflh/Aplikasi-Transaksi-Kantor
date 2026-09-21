# tests/

* `fixtures/` — sample inputs (`sample.pdf` is the digitorus/pdfsign
  `testfile12.pdf`, BSD-2-Clause).
* Go unit/integration coverage lives beside the code (`core/**`, `server/**`,
  `tools/ca-admin`); run `cd core && go test ./spike/ -v` for the end-to-end
  crypto acceptance (sign, verify against the explicit Root CA, tampered-PDF and
  wrong-Root rejection, CSR proof-of-possession, key/cert match).
* Browser end-to-end: `web/e2e/` (added with the browser client).
