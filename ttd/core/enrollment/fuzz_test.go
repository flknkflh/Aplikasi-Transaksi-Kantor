package enrollment_test

import (
	"testing"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
)

// FuzzParseAndValidateCSR must never panic, and must never report
// proof-of-possession on input it did not cryptographically verify.
func FuzzParseAndValidateCSR(f *testing.F) {
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		f.Fatal(err)
	}
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	goodCSR, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "seed"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(goodCSR)
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte{})
	f.Add([]byte("\x30\x80"))                   // indefinite-length SEQUENCE
	f.Add(append([]byte(nil), goodCSR[80:]...)) // header stripped

	f.Fuzz(func(t *testing.T, data []byte) {
		csr, info, err := enrollment.ParseAndValidateCSR(data)
		if err != nil {
			return
		}
		if csr == nil || info == nil {
			t.Fatal("nil result with nil error")
		}
		if !info.ProofOfPossession {
			t.Fatal("validated CSR without proof of possession")
		}
		if info.PublicKeyAlgorithm != keys.Algorithm {
			t.Fatalf("validated non-ML-DSA-65 CSR: %s", info.PublicKeyAlgorithm)
		}
		// A validated CSR's self-signature really must verify.
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("validated CSR fails CheckSignature: %v", err)
		}
	})
}
