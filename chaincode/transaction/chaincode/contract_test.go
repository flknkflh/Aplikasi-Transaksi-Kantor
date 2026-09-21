package chaincode

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

func newTestContext() *contractapi.TransactionContext {
	ctx := &contractapi.TransactionContext{}
	ctx.SetStub(newFakeStub())
	return ctx
}

func mustMarshalEvent(t *testing.T, evt TransactionEvent) string {
	t.Helper()
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(data)
}

func baseEvent() TransactionEvent {
	return TransactionEvent{
		TransactionID:      "txn-1",
		EventSequence:      1,
		EventType:          "SUBMITTED",
		PayloadHash:        "sha256:aaa",
		PreviousEventHash:  "",
		AlgorithmSuite:     allowedAlgorithmSuite,
		ClassicalKeyID:     "classical-1",
		PQCKeyID:           "pqc-1",
		ClassicalSignature: []byte("classical-sig"),
		PQCSignature:       []byte("pqc-sig"),
		IdempotencyKey:     "idem-1",
		CreatedAtServer:    "2026-09-17T12:00:00Z",
		NewStatus:          "VERIFIED",
	}
}

func TestCreateTransactionRejectsDuplicate(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()

	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err == nil {
		t.Fatal("expected error creating a duplicate transaction id")
	}
}

func TestRecordEventHappyPathAndHistory(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()

	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	evt1 := baseEvent()
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, evt1)); err != nil {
		t.Fatalf("record event 1: %v", err)
	}

	evt2 := baseEvent()
	evt2.EventSequence = 2
	evt2.PreviousEventHash = "sha256:aaa"
	evt2.PayloadHash = "sha256:bbb"
	evt2.IdempotencyKey = "idem-2"
	evt2.NewStatus = "ENDORSED"
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, evt2)); err != nil {
		t.Fatalf("record event 2: %v", err)
	}

	txn, err := contract.GetTransaction(ctx, "txn-1")
	if err != nil {
		t.Fatalf("get transaction: %v", err)
	}
	if txn.Status != "ENDORSED" {
		t.Fatalf("expected status ENDORSED, got %s", txn.Status)
	}
	if txn.LatestEventSequence != 2 {
		t.Fatalf("expected latest_event_sequence 2, got %d", txn.LatestEventSequence)
	}

	history, err := contract.GetEventHistory(ctx, "txn-1")
	if err != nil {
		t.Fatalf("get event history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 events in history, got %d", len(history))
	}
	if history[0].EventSequence != 1 || history[1].EventSequence != 2 {
		t.Fatalf("expected history in sequence order, got %d then %d", history[0].EventSequence, history[1].EventSequence)
	}
}

func TestRecordEventRejectsDuplicateIdempotencyKey(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	evt1 := baseEvent()
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, evt1)); err != nil {
		t.Fatalf("record event 1: %v", err)
	}

	// Same idempotency_key reused on what would otherwise be a valid next
	// event: PRD §7 requires this to be rejected as a duplicate/replay.
	replay := baseEvent()
	replay.EventSequence = 2
	replay.PreviousEventHash = "sha256:aaa"
	replay.PayloadHash = "sha256:ccc"
	// IdempotencyKey intentionally left identical to evt1's "idem-1".
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, replay)); err == nil {
		t.Fatal("expected duplicate idempotency_key to be rejected")
	}
}

func TestRecordEventRejectsOutOfOrderSequence(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	skipped := baseEvent()
	skipped.EventSequence = 2 // should be 1 for the first event
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, skipped)); err == nil {
		t.Fatal("expected out-of-order event_sequence to be rejected")
	}
}

func TestRecordEventRejectsBrokenPreviousHashLinkage(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, baseEvent())); err != nil {
		t.Fatalf("record event 1: %v", err)
	}

	evt2 := baseEvent()
	evt2.EventSequence = 2
	evt2.PreviousEventHash = "sha256:wrong-hash"
	evt2.IdempotencyKey = "idem-2"
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, evt2)); err == nil {
		t.Fatal("expected mismatched previous_event_hash to be rejected")
	}
}

func TestRecordEventRejectsNonAllowlistedAlgorithmSuite(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	downgraded := baseEvent()
	downgraded.AlgorithmSuite = "CLASSICAL_ONLY_ED25519_V1"
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, downgraded)); err == nil {
		t.Fatal("expected non-allowlisted algorithm_suite (downgrade attempt) to be rejected")
	}
}

func TestRecordEventRejectsInvalidStatusTransition(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	evt := baseEvent()
	evt.NewStatus = "SETTLED" // DRAFT -> SETTLED is not a valid direct transition
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, evt)); err == nil {
		t.Fatal("expected invalid status transition DRAFT->SETTLED to be rejected")
	}
}

func TestApproveRejectsSelfApproval(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, baseEvent())); err != nil {
		t.Fatalf("record event: %v", err)
	}

	if err := contract.Approve(ctx, "txn-1", 1, "requester-1", "approve", "policy.v1"); err == nil {
		t.Fatal("expected self-approval by the transaction's creator to be rejected")
	}
}

func TestApproveHappyPathAndRejectTransitionsStatus(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	evt := baseEvent()
	evt.NewStatus = "VERIFIED"
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, evt)); err != nil {
		t.Fatalf("record event: %v", err)
	}

	if err := contract.Approve(ctx, "txn-1", 1, "approver-1", "approve", "policy.v1"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// A second, different approver rejecting should move the transaction to
	// REJECTED (VERIFIED -> REJECTED is a valid transition).
	if err := contract.Approve(ctx, "txn-1", 1, "approver-2", "reject", "policy.v1"); err != nil {
		t.Fatalf("reject: %v", err)
	}

	txn, err := contract.GetTransaction(ctx, "txn-1")
	if err != nil {
		t.Fatalf("get transaction: %v", err)
	}
	if txn.Status != "REJECTED" {
		t.Fatalf("expected status REJECTED after a reject decision, got %s", txn.Status)
	}
}

func TestApproveRejectsDuplicateDecisionFromSameApprover(t *testing.T) {
	contract := &TransactionContract{}
	ctx := newTestContext()
	if err := contract.CreateTransaction(ctx, "txn-1", "org-a", "procurement", "transaction.v1", "requester-1"); err != nil {
		t.Fatalf("create transaction: %v", err)
	}
	if err := contract.RecordEvent(ctx, mustMarshalEvent(t, baseEvent())); err != nil {
		t.Fatalf("record event: %v", err)
	}

	if err := contract.Approve(ctx, "txn-1", 1, "approver-1", "approve", "policy.v1"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if err := contract.Approve(ctx, "txn-1", 1, "approver-1", "approve", "policy.v1"); err == nil {
		t.Fatal("expected a second decision from the same approver on the same event to be rejected")
	}
}
