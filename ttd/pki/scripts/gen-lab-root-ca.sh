#!/usr/bin/env sh
# gen-lab-root-ca.sh — LAB Root + Intermediate ML-DSA-65 CA with OpenSSL 3.5.x.
#
# This mirrors what `pqcsign-cli genpki` does in Go, for teams that prefer the
# OpenSSL path. LAB ONLY — the production ceremony is docs/pki-ceremony.md and
# is performed offline with witnesses.
set -eu

OUT="${1:-./lab-pki}"
OPENSSL="${OPENSSL:-openssl}"

mkdir -p "$OUT"
umask 077

echo ">> ML-DSA availability"
"$OPENSSL" list -signature-algorithms | grep -i mldsa || {
  echo "OpenSSL has no ML-DSA — need 3.5.x" >&2; exit 1; }

echo ">> Root CA"
"$OPENSSL" genpkey -algorithm ML-DSA-65 -out "$OUT/root-ca.key.pem"
"$OPENSSL" req -new -x509 -key "$OUT/root-ca.key.pem" -days 3650 \
  -subj "/C=ID/O=PQC PDF Sign Lab/OU=PQC Root CA/CN=PQC PDF Root CA (LAB)" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out "$OUT/root-ca.crt.pem"

echo ">> Intermediate Device Signing CA"
"$OPENSSL" genpkey -algorithm ML-DSA-65 -out "$OUT/intermediate-ca.key.pem"
"$OPENSSL" req -new -key "$OUT/intermediate-ca.key.pem" \
  -subj "/C=ID/O=PQC PDF Sign Lab/OU=PQC Device Signing CA/CN=PQC Device Signing CA (LAB)" \
  -out "$OUT/intermediate-ca.csr.pem"
"$OPENSSL" x509 -req -in "$OUT/intermediate-ca.csr.pem" \
  -CA "$OUT/root-ca.crt.pem" -CAkey "$OUT/root-ca.key.pem" -CAcreateserial \
  -days 1825 \
  -extfile /dev/stdin -extensions v3_int \
  -out "$OUT/intermediate-ca.crt.pem" <<'EXT'
[v3_int]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EXT

cat "$OUT/intermediate-ca.crt.pem" "$OUT/root-ca.crt.pem" > "$OUT/ca-chain-cas.pem"

echo
echo "Lab CA written to $OUT/"
echo "SHA-256 root-ca.crt.pem:"
"$OPENSSL" dgst -sha256 "$OUT/root-ca.crt.pem"
echo
echo "Device certificates: use tools/ca-admin (M7) or 'pqcsign-cli genpki'."
