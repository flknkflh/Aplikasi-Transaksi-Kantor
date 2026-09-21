#!/usr/bin/env bash
# Reports two of the raw numbers PRD §9 asks the Fase 1 spike to measure:
# hybrid-signature envelope size, and submit-to-commit latency. These are
# local test-network numbers only — PRD §9 explicitly warns not to treat
# them as a production SLA.
set -uo pipefail

API=${API_URL:-http://localhost:8080}
N=${1:-5}

echo "== hybrid signature envelope size (from crypto unit tests) =="
echo "See crypto/hybrid_test.go TestHybridEnvelopeSize output, e.g.:"
echo "  classical (Ed25519): 64 bytes, pqc (ML-DSA-65): ~3309 bytes, combined: ~3373 bytes"
echo "Run 'go test ./... -run TestHybridEnvelopeSize -v' in ./crypto for a fresh measurement."
echo

echo "== submit-to-commit latency over $N transactions =="
total=0
for i in $(seq 1 "$N"); do
    txn_id=$(curl -sf -X POST "$API/transactions" -H 'Content-Type: application/json' -d '{
      "organization_id": "org-a", "workflow_type": "procurement",
      "schema_version": "transaction.v1", "created_by": "requester-1"
    }' | jq -r '.id')

    start=$(date +%s%3N)
    curl -sf -X POST "$API/transactions/$txn_id/events" -H 'Content-Type: application/json' -d "{
      \"event_type\": \"SUBMITTED\", \"payload\": {\"i\": $i}, \"new_status\": \"VERIFIED\",
      \"signer_identity\": \"requester-1\", \"idempotency_key\": \"bench-$i-$(date +%s%N)\"
    }" >/dev/null

    committed_at=""
    for _ in $(seq 1 30); do
        committed_at=$(curl -sf "$API/transactions/$txn_id" | jq -r '.events[0].committed_at // empty')
        [ -n "$committed_at" ] && break
        sleep 0.5
    done
    end=$(date +%s%3N)

    if [ -n "$committed_at" ]; then
        elapsed=$((end - start))
        total=$((total + elapsed))
        echo "  run $i: ${elapsed}ms"
    else
        echo "  run $i: TIMED OUT (no commit observed)"
    fi
done
echo "average: $((total / N))ms over $N runs"
