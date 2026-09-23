#!/usr/bin/env bash
# Admin-side tool (run on the CENTRAL machine, after network/bootstrap.sh):
# mints a brand-new peer identity via the live Fabric CA and packages
# everything an office's office-node EXE needs to become a real, additional
# peer on the shared ledger — into one file the admin hands to that office
# (email/USB/secure transfer). See ../MULTI-HOST-LAB.md and
# docs/adr/0011-office-node.md for why this is the one step that MUST stay a
# deliberate admin action (a permissioned network cannot let itself be
# joined by anyone who merely has the software).
#
#   cd network && bash tools/office-node/pack-join.sh "Kantor Cabang C"
#
# Requires: bootstrap.sh already run once (ca_org2 + orderer + peer0.org2
# containers up — this reads their already-issued material and, for the new
# peer, talks to the live ca_org2 enrollment API on localhost:8054).
set -euo pipefail

ORG_LABEL="${1:?usage: pack-join.sh \"<nama kantor>\"}"
PEER_ID="${2:-peer$(date +%s | tail -c 4)}"   # unique-ish peer name, e.g. peer1737

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SAMPLES_DIR="${NETWORK_DIR}/vendor/fabric-samples"
TESTNET_DIR="${SAMPLES_DIR}/test-network"
ORGS_DIR="${TESTNET_DIR}/organizations"

export PATH="${SAMPLES_DIR}/bin:${PATH}"
export FABRIC_CA_CLIENT_HOME="${TESTNET_DIR}/organizations/peerOrganizations/org2.example.com/"

CA_CERT="${ORGS_DIR}/fabric-ca/org2/ca-cert.pem"
[ -f "${CA_CERT}" ] || { echo "!! ${CA_CERT} not found — run network/bootstrap.sh first (with its default -ca flag)"; exit 1; }

PEER_FQDN="${PEER_ID}.org2.example.com"
PEER_HOME="${ORGS_DIR}/peerOrganizations/org2.example.com/peers/${PEER_FQDN}"
PEER_SECRET="${PEER_ID}pw-$(date +%s)"   # random-ish enrollment secret, one-time use

if [ -d "${PEER_HOME}" ]; then
  echo "!! ${PEER_FQDN} already enrolled at ${PEER_HOME} — pick a different --peer-id or delete it first"
  exit 1
fi

echo ">> registering ${PEER_FQDN} with ca_org2 (localhost:8054)"
fabric-ca-client register --caname ca-org2 \
  --id.name "${PEER_ID}" --id.secret "${PEER_SECRET}" --id.type peer \
  --tls.certfiles "${CA_CERT}"

echo ">> enrolling MSP identity"
fabric-ca-client enroll -u "https://${PEER_ID}:${PEER_SECRET}@localhost:8054" --caname ca-org2 \
  -M "${PEER_HOME}/msp" --tls.certfiles "${CA_CERT}"
cp "${ORGS_DIR}/peerOrganizations/org2.example.com/msp/config.yaml" "${PEER_HOME}/msp/config.yaml"

echo ">> enrolling TLS identity (CN=${PEER_FQDN}; office-node will run this on the office's own machine)"
fabric-ca-client enroll -u "https://${PEER_ID}:${PEER_SECRET}@localhost:8054" --caname ca-org2 \
  -M "${PEER_HOME}/tls" --enrollment.profile tls \
  --csr.hosts "${PEER_FQDN}" --csr.hosts localhost --csr.hosts 127.0.0.1 \
  --tls.certfiles "${CA_CERT}"
cp "${PEER_HOME}/tls/tlscacerts/"* "${PEER_HOME}/tls/ca.crt"
cp "${PEER_HOME}/tls/signcerts/"* "${PEER_HOME}/tls/server.crt"
cp "${PEER_HOME}/tls/keystore/"* "${PEER_HOME}/tls/server.key"

echo ">> assembling the join package"
OUT_DIR="${NETWORK_DIR}/tools/office-node/packages"
mkdir -p "${OUT_DIR}"
STAGE="$(mktemp -d)"
mkdir -p "${STAGE}/msp" "${STAGE}/tls" "${STAGE}/admin-msp"
cp -r "${PEER_HOME}/msp/"* "${STAGE}/msp/"
cp "${PEER_HOME}/tls/ca.crt" "${PEER_HOME}/tls/server.crt" "${PEER_HOME}/tls/server.key" "${STAGE}/tls/"
cp "${ORGS_DIR}/ordererOrganizations/example.com/msp/tlscacerts/"* "${STAGE}/orderer-tls-ca.crt"
cp "${TESTNET_DIR}/channel-artifacts/ledgerchannel.block" "${STAGE}/genesis.block"
# `peer channel join` (and later chaincode approve/install) is an administrative
# act on the org's MSP, not something the peer's own server identity is allowed
# to do (Fabric's default Admins policy requires OU=admin) — so office-node needs
# an admin identity too, used ONLY for these one-off local CLI calls, never for
# the long-running peer process. v1 SIMPLIFICATION, noted in ADR-0011: this reuses
# Org2's one existing admin identity rather than minting a join-scoped one, so
# every office's package carries the same org-wide administrative credential.
# The more correct version has the CENTRAL admin run the join remotely instead
# (targeting the new peer's address from its own held admin identity, never
# distributed) — left as a follow-up once this mechanism is proven.
cp -r "${ORGS_DIR}/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/"* "${STAGE}/admin-msp/"

cat > "${STAGE}/join.json" <<JSON
{
  "org_label": "${ORG_LABEL}",
  "msp_id": "Org2MSP",
  "peer_id": "${PEER_FQDN}",
  "channel_name": "ledgerchannel",
  "peer_port": 9061,
  "peer_chaincode_port": 9062,
  "peer_operations_port": 9455,
  "orderer_address": "orderer.example.com:7050",
  "orderer_hostname": "orderer.example.com"
}
JSON

PKG="${OUT_DIR}/join-${PEER_ID}.zip"
( cd "${STAGE}" && zip -qr "${PKG}" . )
rm -rf "${STAGE}"

echo
echo "  Join package : ${PKG}"
echo "  Untuk        : ${ORG_LABEL} (identitas: ${PEER_FQDN}, MSP Org2MSP)"
echo "  Kirim file itu ke komputer kantor tsb, lalu di sana jalankan:"
echo "    office-node join ${PKG##*/}"
echo "    office-node start"
echo
echo "  PENTING: file ini berisi kunci privat identitas kantor tsb di jaringan blockchain —"
echo "  kirim lewat jalur aman (bukan email tanpa enkripsi/chat publik), dan hapus salinan di sini"
echo "  setelah terkirim kalau tidak perlu diarsipkan."
