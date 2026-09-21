package crypto

import (
	"bytes"
	"testing"
)

func TestHybridKEMRoundTrip(t *testing.T) {
	recipient, err := GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatalf("generate recipient keypair: %v", err)
	}

	senderShared, ephemeralPub, ciphertext, err := HybridEncapsulate(recipient.PublicKey())
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	recipientShared, err := HybridDecapsulate(recipient, ephemeralPub, ciphertext)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}

	if !bytes.Equal(senderShared, recipientShared) {
		t.Fatal("expected sender and recipient to derive the same shared key")
	}
	if len(senderShared) != 32 {
		t.Fatalf("expected a 32-byte derived key, got %d bytes", len(senderShared))
	}
}

func TestHybridKEMWrongCiphertextProducesDifferentKey(t *testing.T) {
	recipient, err := GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatalf("generate recipient keypair: %v", err)
	}
	other, err := GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatalf("generate other keypair: %v", err)
	}

	senderShared, _, ciphertext, err := HybridEncapsulate(recipient.PublicKey())
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	// Decapsulating with the wrong X25519 ephemeral public (simulating a
	// tampered/mismatched transport) must not reproduce the sender's key.
	_, wrongEphemeralPub, _, err := HybridEncapsulate(other.PublicKey())
	if err != nil {
		t.Fatalf("encapsulate (other): %v", err)
	}

	mismatchedShared, err := HybridDecapsulate(recipient, wrongEphemeralPub, ciphertext)
	if err != nil {
		// A parse/ECDH error is an acceptable outcome too — either way the
		// keys must not match.
		return
	}
	if bytes.Equal(senderShared, mismatchedShared) {
		t.Fatal("expected mismatched ephemeral public to derive a different shared key")
	}
}
