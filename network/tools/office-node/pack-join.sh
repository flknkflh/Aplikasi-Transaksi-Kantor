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
#   ORDERER_REACHABLE_ADDR=192.168.1.10:7050 bash tools/office-node/pack-join.sh "Kantor Cabang C"
#
# Requires: bootstrap.sh already run once (ca_org2 + orderer + peer0.org2
# containers up — this reads their already-issued material and, for the new
# peer, talks to the live ca_org2 enrollment API on localhost:8054).
#
# ORDERER_REACHABLE_ADDR (env, optional): the orderer's channel-config hostname
# ("orderer.example.com:7050") is normally unresolvable from an office machine
# outside this Docker network (docs/adr/0011 bug #4) — office-node needs to
# know where to actually dial instead. Defaults to 127.0.0.1:7050 (this
# machine, e.g. same-machine testing); for a genuinely remote office, set this
# to the orderer host's real LAN/public address:port.
set -euo pipefail

ORG_LABEL="${1:?usage: pack-join.sh \"<nama kantor>\"}"
PEER_ID="${2:-peer$(date +%s | tail -c 4)}"   # unique-ish peer name, e.g. peer1737
ORDERER_REACHABLE_ADDR="${ORDERER_REACHABLE_ADDR:-127.0.0.1:7050}"

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
mkdir -p "${STAGE}/msp" "${STAGE}/tls"
cp -r "${PEER_HOME}/msp/"* "${STAGE}/msp/"
cp "${PEER_HOME}/tls/ca.crt" "${PEER_HOME}/tls/server.crt" "${PEER_HOME}/tls/server.key" "${STAGE}/tls/"
cp "${ORGS_DIR}/ordererOrganizations/example.com/msp/tlscacerts/"* "${STAGE}/orderer-tls-ca.crt"
cp "${TESTNET_DIR}/channel-artifacts/ledgerchannel.block" "${STAGE}/genesis.block"
# `peer channel join` is an administrative act on the org's MSP, not something the
# peer's own server identity is allowed to do (Fabric's default Admins policy
# requires OU=admin). Fabric has no narrower "can only join a channel" role — any
# OU=admin identity can do any admin operation — so the only real choice is WHO
# holds that identity, not how it's scoped:
#   INCLUDE_ADMIN_MSP=true  (default): bundle a copy of the org's admin MSP into
#     the package; office-node joins itself on first `start`. Simple, one file to
#     hand over, but every office's package then carries the same org-wide
#     administrative credential.
#   INCLUDE_ADMIN_MSP=false: office-node never receives an admin identity at all;
#     it starts the peer and waits. The central admin runs remote-join.sh instead,
#     using ITS OWN retained admin identity, which never leaves this machine.
#     Stronger, at the cost of one more manual step per office.
INCLUDE_ADMIN_MSP="${INCLUDE_ADMIN_MSP:-true}"
if [ "${INCLUDE_ADMIN_MSP}" = "true" ]; then
  mkdir -p "${STAGE}/admin-msp"
  cp -r "${ORGS_DIR}/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/"* "${STAGE}/admin-msp/"
fi

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
  "orderer_hostname": "orderer.example.com",
  "orderer_reachable_addr": "${ORDERER_REACHABLE_ADDR}"
}
JSON

PKG="${OUT_DIR}/join-${PEER_ID}.zip"
( cd "${STAGE}" && zip -qr "${PKG}" . )
rm -rf "${STAGE}"

echo
echo "  Join package : ${PKG}"
echo "  Untuk        : ${ORG_LABEL} (identitas: ${PEER_FQDN}, MSP Org2MSP)"
echo "  Orderer dituju di alamat : ${ORDERER_REACHABLE_ADDR}"
echo "    (kalau kantor itu di komputer/jaringan lain, ulangi dengan"
echo "     ORDERER_REACHABLE_ADDR=<ip-lan-server-ini>:7050 sebelum mengirim paketnya)"
echo "  Kirim file itu ke komputer kantor tsb, lalu di sana jalankan:"
echo "    office-node join ${PKG##*/}"
echo "    office-node start"
if [ "${INCLUDE_ADMIN_MSP}" != "true" ]; then
  echo
  echo "  Paket ini TIDAK berisi kredensial admin (INCLUDE_ADMIN_MSP=false) — setelah"
  echo "  peer kantor itu \`start\` dan bisa dijangkau, join-kan dari sini dengan:"
  echo "    bash tools/office-node/remote-join.sh ${PEER_ID} <alamat-peer-kantor>:9061"
fi
echo
echo "  PENTING: file ini berisi kunci privat identitas kantor tsb di jaringan blockchain —"
echo "  kirim lewat jalur aman (bukan email tanpa enkripsi/chat publik), dan hapus salinan di sini"
echo "  setelah terkirim kalau tidak perlu diarsipkan."
