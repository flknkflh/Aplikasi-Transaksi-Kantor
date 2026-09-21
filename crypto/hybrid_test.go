package crypto

import (
	"testing"
)

func testIdentityAndKeys(t *testing.T) (SigningIdentity, VerificationKeys) {
	t.Helper()

	classical, err := GenerateClassicalKeyPair()
	if err != nil {
		t.Fatalf("generate classical key: %v", err)
	}
	pqcPublic, pqcPrivate, err := GenerateMLDSAKeyPair()
	if err != nil {
		t.Fatalf("generate ML-DSA-65 key: %v", err)
	}

	identity := SigningIdentity{
		ClassicalKeyID:   "classical-key-1",
		ClassicalPrivate: classical.Private,
		PQCKeyID:         "pqc-key-1",
		PQCPrivate:       pqcPrivate,
	}
	keys := VerificationKeys{
		ClassicalPublic: classical.Public,
		PQCPublic:       pqcPublic,
	}
	return identity, keys
}

func testContext() SigningContext {
	return SigningContext{
		Application:     "pqc-ledger",
		Environment:     "test",
		TransactionType: "ASSET_HANDOVER_CONFIRMED",
		SchemaVersion:   "transaction.v1",
		TransactionID:   "txn_test_001",
	}
}

func TestHybridSignVerifyRoundTrip(t *testing.T) {
	identity, keys := testIdentityAndKeys(t)
	ctx := testContext()
	payload := map[string]interface{}{"asset_id": "asset-123", "event_sequence": 4}

	sig, payloadHash, err := SignHybrid(identity, ctx, payload)
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}
	if payloadHash == "" {
		t.Fatal("expected non-empty payload hash")
	}

	result, err := VerifyHybrid(keys, sig, ctx, payload)
	if err != nil {
		t.Fatalf("verify hybrid: %v", err)
	}
	if !result.OK() {
		t.Fatalf("expected valid hybrid signature to verify OK, got %+v", result)
	}
}

func TestHybridVerifyRejectsTamperedPayload(t *testing.T) {
	identity, keys := testIdentityAndKeys(t)
	ctx := testContext()
	payload := map[string]interface{}{"asset_id": "asset-123", "event_sequence": 4}

	sig, _, err := SignHybrid(identity, ctx, payload)
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}

	tampered := map[string]interface{}{"asset_id": "asset-123", "event_sequence": 5}
	result, err := VerifyHybrid(keys, sig, ctx, tampered)
	if err != nil {
		t.Fatalf("verify hybrid: %v", err)
	}
	if result.OK() {
		t.Fatal("expected tampered payload to fail verification")
	}
	if result.ClassicalValid || result.PQCValid {
		t.Fatalf("expected both signature halves to fail on tampered payload, got %+v", result)
	}
}

func TestHybridVerifyRejectsWrongContext(t *testing.T) {
	identity, keys := testIdentityAndKeys(t)
	ctx := testContext()
	payload := map[string]interface{}{"asset_id": "asset-123"}

	sig, _, err := SignHybrid(identity, ctx, payload)
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}

	// Same payload, different transaction ID: simulates cross-protocol /
	// cross-transaction replay, which PRD §7 requires the signing context to
	// prevent.
	wrongCtx := ctx
	wrongCtx.TransactionID = "txn_test_999"

	result, err := VerifyHybrid(keys, sig, wrongCtx, payload)
	if err != nil {
		t.Fatalf("verify hybrid: %v", err)
	}
	if result.OK() {
		t.Fatal("expected signature bound to one transaction ID to fail verification under another")
	}
}

func TestHybridVerifyRejectsUnknownAlgorithmSuite(t *testing.T) {
	identity, keys := testIdentityAndKeys(t)
	ctx := testContext()
	payload := map[string]interface{}{"asset_id": "asset-123"}

	sig, _, err := SignHybrid(identity, ctx, payload)
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}

	// Simulate a downgrade attempt: same signatures, but claiming a suite
	// that isn't allow-listed (e.g. a classical-only suite).
	sig.AlgorithmSuite = AlgorithmSuite("CLASSICAL_ONLY_ED25519_V1")

	result, err := VerifyHybrid(keys, sig, ctx, payload)
	if err == nil {
		t.Fatal("expected an error for a non-allow-listed algorithm_suite (downgrade attempt)")
	}
	if result.OK() {
		t.Fatal("expected downgrade attempt to never verify as OK")
	}
}

func TestHybridVerifyRejectsClassicalOnlyForgery(t *testing.T) {
	// A forger who only compromised the classical key (but not the PQC key)
	// must not be able to produce a signature that verifies.
	identity, keys := testIdentityAndKeys(t)
	forgerIdentity, _ := testIdentityAndKeys(t)
	ctx := testContext()
	payload := map[string]interface{}{"asset_id": "asset-123"}

	sig, _, err := SignHybrid(identity, ctx, payload)
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}

	// Swap in a PQC signature from a different (forger's) key.
	forgedPQCSig, _, err := SignHybrid(forgerIdentity, ctx, payload)
	if err != nil {
		t.Fatalf("sign forger hybrid: %v", err)
	}
	sig.PQCSignature = forgedPQCSig.PQCSignature

	result, err := VerifyHybrid(keys, sig, ctx, payload)
	if err != nil {
		t.Fatalf("verify hybrid: %v", err)
	}
	if result.OK() {
		t.Fatal("expected mismatched PQC signature to fail verification even though classical half is valid")
	}
	if !result.ClassicalValid {
		t.Fatal("expected classical half to still verify independently")
	}
	if result.PQCValid {
		t.Fatal("expected PQC half to fail since it was signed by a different key")
	}
}

// TestHybridEnvelopeSize reports the raw signature sizes for
// SuiteHybridEd25519MLDSA65V1, feeding the PRD §9 requirement to benchmark
// "ukuran transaction envelope dengan signature hybrid" (envelope size with
// hybrid signatures) before treating any number as a production expectation.
func TestHybridEnvelopeSize(t *testing.T) {
	identity, _ := testIdentityAndKeys(t)
	ctx := testContext()
	payload := map[string]interface{}{
		"asset_id":       "asset-123",
		"event_type":     "ASSET_HANDOVER_CONFIRMED",
		"event_sequence": 4,
	}

	sig, _, err := SignHybrid(identity, ctx, payload)
	if err != nil {
		t.Fatalf("sign hybrid: %v", err)
	}

	t.Logf("classical (Ed25519) signature: %d bytes", len(sig.ClassicalSignature))
	t.Logf("pqc (ML-DSA-65) signature: %d bytes", len(sig.PQCSignature))
	t.Logf("combined signature bytes: %d bytes", len(sig.ClassicalSignature)+len(sig.PQCSignature))
}
