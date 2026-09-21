package enrollment_test

import (
	"testing"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
)

func deviceKeyPEM(t *testing.T) []byte {
	t.Helper()
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		t.Fatal(err)
	}
	p, err := keys.MarshalPKCS8PEM(sk)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCreateAndValidateCSR(t *testing.T) {
	key := deviceKeyPEM(t)
	csrPEM, err := enrollment.CreateDeviceCSR(key, enrollment.Request{
		CommonName:   "Device 1",
		Organization: "Lab",
		Platform:     "windows",
	})
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	_, info, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		t.Fatalf("validate CSR: %v", err)
	}
	if !info.ProofOfPossession {
		t.Fatal("expected proof of possession")
	}
	if info.PublicKeyAlgorithm != keys.Algorithm {
		t.Fatalf("algorithm = %q, want %q", info.PublicKeyAlgorithm, keys.Algorithm)
	}
}

func TestValidateCSRRejectsTamperedSignature(t *testing.T) {
	key := deviceKeyPEM(t)
	csrPEM, err := enrollment.CreateDeviceCSR(key, enrollment.Request{CommonName: "Device 2"})
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the DER body (inside the PEM) to break the self-signature.
	for i := len(csrPEM) / 2; i < len(csrPEM); i++ {
		if csrPEM[i] >= 'A' && csrPEM[i] <= 'Z' {
			csrPEM[i] = 'a'
			break
		}
	}
	if _, _, err := enrollment.ParseAndValidateCSR(csrPEM); err == nil {
		t.Fatal("expected validation failure for tampered CSR")
	}
}

func TestCreateDeviceCSRRejectsNonMLDSAKey(t *testing.T) {
	if _, err := enrollment.CreateDeviceCSR([]byte("garbage"), enrollment.Request{CommonName: "x"}); err == nil {
		t.Fatal("expected error for non-ML-DSA key input")
	}
}
