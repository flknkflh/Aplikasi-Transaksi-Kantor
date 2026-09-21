#!/usr/bin/env bash
# End-to-end smoke test: create -> sign -> submit -> commit -> index -> audit
# verify, plus the duplicate-idempotency-key rejection required by the PRD
# §12 MVP acceptance criteria. Requires the full stack running
# (infra/docker-compose.yml) and the Fabric test network up
# (network/bootstrap.sh).
set -uo pipefail

API=${API_URL:-http://localhost:8080}
AUDIT=${AUDIT_URL:-http://localhost:8081}
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

wait_for() {
    local url=$1 name=$2
    for _ in $(seq 1 30); do
        if curl -sf "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "timed out waiting for $name at $url" >&2
    exit 1
}

echo "== waiting for services =="
wait_for "$API/healthz" api
wait_for "$AUDIT/healthz" audit-service

echo "== create transaction =="
CREATE_RESP=$(curl -sf -X POST "$API/transactions" -H 'Content-Type: application/json' -d '{
  "organization_id": "org-a",
  "workflow_type": "procurement",
  "schema_version": "transaction.v1",
  "created_by": "requester-1"
}')
TXN_ID=$(echo "$CREATE_RESP" | jq -r '.id')
if [ -n "$TXN_ID" ] && [ "$TXN_ID" != "null" ]; then
    pass "create transaction ($TXN_ID)"
else
    fail "create transaction: $CREATE_RESP"
    exit 1
fi

echo "== record signed event =="
IDEM_KEY="idem-smoke-$(date +%s)"
EVENT_RESP=$(curl -sf -X POST "$API/transactions/$TXN_ID/events" -H 'Content-Type: application/json' -d "{
  \"event_type\": \"SUBMITTED\",
  \"payload\": {\"item\": \"laptop\", \"quantity\": 3},
  \"new_status\": \"VERIFIED\",
  \"signer_identity\": \"requester-1\",
  \"idempotency_key\": \"$IDEM_KEY\"
}")
EVENT_STATUS=$(echo "$EVENT_RESP" | jq -r '.status')
if [ "$EVENT_STATUS" = "queued" ]; then
    pass "record event queued"
else
    fail "record event: $EVENT_RESP"
fi

echo "== duplicate idempotency_key must be rejected =="
DUP_STATUS=$(curl -s -o /tmp/dup_resp.json -w '%{http_code}' -X POST "$API/transactions/$TXN_ID/events" -H 'Content-Type: application/json' -d "{
  \"event_type\": \"SUBMITTED\",
  \"payload\": {\"item\": \"laptop\", \"quantity\": 3},
  \"new_status\": \"VERIFIED\",
  \"signer_identity\": \"requester-1\",
  \"idempotency_key\": \"$IDEM_KEY\"
}")
if [ "$DUP_STATUS" -ge 400 ]; then
    pass "duplicate idempotency_key rejected (HTTP $DUP_STATUS)"
else
    fail "duplicate idempotency_key was accepted (HTTP $DUP_STATUS): $(cat /tmp/dup_resp.json)"
fi

echo "== waiting for indexer to observe the commit =="
COMMITTED=0
for _ in $(seq 1 30); do
    TXN_VIEW=$(curl -sf "$API/transactions/$TXN_ID")
    COMMITTED_AT=$(echo "$TXN_VIEW" | jq -r '.events[0].committed_at // empty')
    if [ -n "$COMMITTED_AT" ]; then
        COMMITTED=1
        break
    fi
    sleep 2
done
if [ "$COMMITTED" -eq 1 ]; then
    pass "event committed and indexed (committed_at=$COMMITTED_AT)"
else
    fail "event never showed committed_at within timeout — check api/indexer/outbox_event logs"
fi

echo "== approvals =="
curl -sf -X POST "$API/transactions/$TXN_ID/approve" -H 'Content-Type: application/json' -d '{
  "event_sequence": 1, "approver_id": "approver-1", "decision": "approve", "policy_version": "handover-policy.v1"
}' >/dev/null && pass "approver-1 approval queued" || fail "approver-1 approval request failed"

echo "== independent audit verification =="
VERIFIED=0
for _ in $(seq 1 15); do
    RECEIPT=$(curl -sf "$AUDIT/verify/transactions/$TXN_ID" || true)
    OVERALL=$(echo "$RECEIPT" | jq -r '.overall_valid // empty')
    if [ "$OVERALL" = "true" ]; then
        VERIFIED=1
        break
    fi
    sleep 2
done
if [ "$VERIFIED" -eq 1 ]; then
    pass "audit-service verified the transaction independently (overall_valid=true)"
else
    fail "audit-service did not report overall_valid=true: $RECEIPT"
fi

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
