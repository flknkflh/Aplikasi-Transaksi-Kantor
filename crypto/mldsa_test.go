package crypto

import "testing"

func TestMLDSAKeySizesAndRoundTrip(t *testing.T) {
	pub, priv, err := GenerateMLDSAKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pub) != 1952 {
		t.Fatalf("ML-DSA-65 public key should be 1952 bytes, got %d", len(pub))
	}
	if len(priv) != 32 {
		t.Fatalf("private key is the 32-byte FIPS 204 seed, got %d bytes", len(priv))
	}

	msg := []byte("hello ledger")
	sig, err := SignMLDSA(priv, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 3309 {
		t.Fatalf("ML-DSA-65 signature should be 3309 bytes, got %d", len(sig))
	}
	ok, err := VerifyMLDSA(pub, msg, sig)
	if err != nil || !ok {
		t.Fatalf("expected valid signature, got ok=%v err=%v", ok, err)
	}
}

func TestMLDSASigningDoesNotConsumeCallerKey(t *testing.T) {
	// Regression for a bug in the earlier liboqs binding, where signing
	// zeroed the caller's key buffer after one use.
	pub, priv, err := GenerateMLDSAKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for i := 0; i < 3; i++ {
		sig, err := SignMLDSA(priv, []byte("msg"))
		if err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
		if ok, err := VerifyMLDSA(pub, []byte("msg"), sig); err != nil || !ok {
			t.Fatalf("signature #%d did not verify: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestMLDSAVerifyRejectsTamperedMessageAndWrongKey(t *testing.T) {
	pub, priv, _ := GenerateMLDSAKeyPair()
	otherPub, _, _ := GenerateMLDSAKeyPair()
	sig, err := SignMLDSA(priv, []byte("original"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if ok, err := VerifyMLDSA(pub, []byte("tampered"), sig); err != nil || ok {
		t.Fatalf("tampered message must not verify: ok=%v err=%v", ok, err)
	}
	if ok, err := VerifyMLDSA(otherPub, []byte("original"), sig); err != nil || ok {
		t.Fatalf("signature must not verify under another key: ok=%v err=%v", ok, err)
	}
}

func TestMLDSARejectsMalformedKeys(t *testing.T) {
	if _, err := SignMLDSA([]byte("too short"), []byte("m")); err == nil {
		t.Fatal("expected an error for a private key that is not a 32-byte seed")
	}
	if ok, err := VerifyMLDSA([]byte("not a public key"), []byte("m"), []byte("s")); err == nil || ok {
		t.Fatalf("expected an error for a malformed public key, got ok=%v err=%v", ok, err)
	}
}
