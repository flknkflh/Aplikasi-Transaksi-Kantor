#!/usr/bin/env bash
# Reads a transaction and its event history straight from the peer (no API, no
# Postgres) so the ledger can be checked independently of the application.
#
#   network/query-transaction.sh txn_<uuid>      # run where the Fabric binaries run (Linux/WSL)
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <transaction-id>"; exit 2; }
TN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vendor/fabric-samples/test-network"
export PATH="$TN/../bin:$PATH" FABRIC_CFG_PATH="$TN/../config"
export CORE_PEER_TLS_ENABLED=true CORE_PEER_LOCALMSPID=Org1MSP CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
q() { peer chaincode query -C ledgerchannel -n transaction -c "{\"function\":\"$1\",\"Args\":[\"$2\"]}"; }
echo "== GetTransaction"; q GetTransaction "$1" | jq -c '{id,status,created_by,latest_event_sequence}'
echo "== GetEventHistory"
q GetEventHistory "$1" | jq -c '.[] | {seq: .event_sequence, type: .event_type, suite: .algorithm_suite, hash: .payload_hash, prev: .previous_event_hash, classical_sig_b64_len: (.classical_signature|length), pqc_sig_b64_len: (.pqc_signature|length)}'
echo "== ledger"; peer channel getinfo -c ledgerchannel 2>&1 | tail -1
