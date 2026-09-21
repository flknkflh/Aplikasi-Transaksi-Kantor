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

func mustMarshalEvent(t *testing.T, evt CustodyEvent) string {
	t.Helper()
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(data)
}

func baseCustodyEvent() CustodyEvent {
	return CustodyEvent{
		AssetID:            "asset-1",
		EventSequence:      1,
		FromParty:          "",
		ToParty:            "warehouse-a",
		LocationZone:       "zone-1",
		PayloadHash:        "sha256:aaa",
		PreviousEventHash:  "",
		AlgorithmSuite:     allowedAlgorithmSuite,
		ClassicalKeyID:     "classical-1",
		PQCKeyID:           "pqc-1",
		ClassicalSignature: []byte("classical-sig"),
		PQCSignature:       []byte("pqc-sig"),
		IdempotencyKey:     "idem-1",
		CreatedAtServer:    "2026-09-17T12:00:00Z",
		NewStatus:          "RECEIVED",
	}
}

func TestCreateAssetRejectsDuplicate(t *testing.T) {
	contract := &AssetContract{}
	ctx := newTestContext()

	if err := contract.CreateAsset(ctx, "asset-1", "org-a", "TAG-001"); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := contract.CreateAsset(ctx, "asset-1", "org-a", "TAG-001"); err == nil {
		t.Fatal("expected error creating a duplicate asset id")
	}
}

func TestRecordCustodyEventHappyPathAndHistory(t *testing.T) {
	contract := &AssetContract{}
	ctx := newTestContext()
	if err := contract.CreateAsset(ctx, "asset-1", "org-a", "TAG-001"); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	evt1 := baseCustodyEvent()
	if err := contract.RecordCustodyEvent(ctx, mustMarshalEvent(t, evt1)); err != nil {
		t.Fatalf("record custody event 1: %v", err)
	}

	evt2 := baseCustodyEvent()
	evt2.EventSequence = 2
	evt2.PreviousEventHash = "sha256:aaa"
	evt2.PayloadHash = "sha256:bbb"
	evt2.IdempotencyKey = "idem-2"
	evt2.NewStatus = "INSPECTED"
	if err := contract.RecordCustodyEvent(ctx, mustMarshalEvent(t, evt2)); err != nil {
		t.Fatalf("record custody event 2: %v", err)
	}

	asset, err := contract.GetAsset(ctx, "asset-1")
	if err != nil {
		t.Fatalf("get asset: %v", err)
	}
	if asset.Status != "INSPECTED" {
		t.Fatalf("expected status INSPECTED, got %s", asset.Status)
	}

	history, err := contract.GetCustodyHistory(ctx, "asset-1")
	if err != nil {
		t.Fatalf("get custody history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 events in history, got %d", len(history))
	}
	if history[0].EventSequence != 1 || history[1].EventSequence != 2 {
		t.Fatalf("expected history in sequence order, got %d then %d", history[0].EventSequence, history[1].EventSequence)
	}
}

func TestRecordCustodyEventRejectsInvalidLifecycleTransition(t *testing.T) {
	contract := &AssetContract{}
	ctx := newTestContext()
	if err := contract.CreateAsset(ctx, "asset-1", "org-a", "TAG-001"); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	evt := baseCustodyEvent()
	evt.NewStatus = "ISSUED" // CREATED -> ISSUED is not a valid direct transition
	if err := contract.RecordCustodyEvent(ctx, mustMarshalEvent(t, evt)); err == nil {
		t.Fatal("expected invalid lifecycle transition CREATED->ISSUED to be rejected")
	}
}

func TestRecordCustodyEventAllowsRealisticLoop(t *testing.T) {
	contract := &AssetContract{}
	ctx := newTestContext()
	if err := contract.CreateAsset(ctx, "asset-1", "org-a", "TAG-001"); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	steps := []string{"RECEIVED", "INSPECTED", "STORED", "ISSUED", "TRANSFERRED", "RECEIVED", "INSPECTED", "STORED", "RETIRED"}
	prevHash := ""
	for i, status := range steps {
		evt := baseCustodyEvent()
		evt.EventSequence = i + 1
		evt.PreviousEventHash = prevHash
		evt.PayloadHash = "sha256:step" + status
		evt.IdempotencyKey = "idem-" + status + "-" + string(rune('0'+i))
		evt.NewStatus = status
		if err := contract.RecordCustodyEvent(ctx, mustMarshalEvent(t, evt)); err != nil {
			t.Fatalf("step %d (%s): %v", i, status, err)
		}
		prevHash = evt.PayloadHash
	}

	asset, err := contract.GetAsset(ctx, "asset-1")
	if err != nil {
		t.Fatalf("get asset: %v", err)
	}
	if asset.Status != "RETIRED" {
		t.Fatalf("expected final status RETIRED, got %s", asset.Status)
	}
}

func TestRecordCustodyEventRejectsDuplicateIdempotencyKey(t *testing.T) {
	contract := &AssetContract{}
	ctx := newTestContext()
	if err := contract.CreateAsset(ctx, "asset-1", "org-a", "TAG-001"); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := contract.RecordCustodyEvent(ctx, mustMarshalEvent(t, baseCustodyEvent())); err != nil {
		t.Fatalf("record custody event 1: %v", err)
	}

	replay := baseCustodyEvent()
	replay.EventSequence = 2
	replay.PreviousEventHash = "sha256:aaa"
	replay.PayloadHash = "sha256:ccc"
	replay.NewStatus = "INSPECTED"
	// IdempotencyKey intentionally left identical to evt1's "idem-1".
	if err := contract.RecordCustodyEvent(ctx, mustMarshalEvent(t, replay)); err == nil {
		t.Fatal("expected duplicate idempotency_key to be rejected")
	}
}

func TestRecordCustodyEventRejectsNonAllowlistedAlgorithmSuite(t *testing.T) {
	contract := &AssetContract{}
	ctx := newTestContext()
	if err := contract.CreateAsset(ctx, "asset-1", "org-a", "TAG-001"); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	downgraded := baseCustodyEvent()
	downgraded.AlgorithmSuite = "CLASSICAL_ONLY_ED25519_V1"
	if err := contract.RecordCustodyEvent(ctx, mustMarshalEvent(t, downgraded)); err == nil {
		t.Fatal("expected non-allowlisted algorithm_suite (downgrade attempt) to be rejected")
	}
}
