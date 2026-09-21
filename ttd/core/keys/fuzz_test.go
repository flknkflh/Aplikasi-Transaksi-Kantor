package keys_test

import (
	"testing"

	"example.internal/pqc-pdf-sign/core/keys"
)

// FuzzParsePKCS8 must never panic and must never return a key together with a
// nil error for input that is not a well-formed ML-DSA-65 PKCS#8 blob.
func FuzzParsePKCS8(f *testing.F) {
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		f.Fatal(err)
	}
	good, _ := keys.MarshalPKCS8(sk)
	goodPEM, _ := keys.MarshalPKCS8PEM(sk)
	f.Add(good)
	f.Add(goodPEM)
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nZ\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("\x30\x82\xff\xff"))                 // ASN.1 SEQUENCE claiming a huge length
	f.Add(append([]byte(nil), good[:len(good)/2]...)) // truncated

	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := keys.ParsePKCS8(data)
		if err == nil && k == nil {
			t.Fatal("nil key with nil error")
		}
		if err == nil {
			// A returned key must round-trip.
			b, mErr := keys.MarshalPKCS8(k)
			if mErr != nil {
				t.Fatalf("accepted key fails to marshal: %v", mErr)
			}
			if k2, pErr := keys.ParsePKCS8(b); pErr != nil || !k.PublicKey().Equal(k2.PublicKey()) {
				t.Fatalf("accepted key does not round-trip: %v", pErr)
			}
		}
	})
}
