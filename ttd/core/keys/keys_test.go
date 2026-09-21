package keys_test

import (
	"bytes"
	"testing"

	"example.internal/pqc-pdf-sign/core/keys"
)

func TestGenerateMarshalRoundTrip(t *testing.T) {
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := keys.MarshalPKCS8(sk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := keys.ParsePKCS8(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !sk.PublicKey().Equal(back.PublicKey()) {
		t.Fatal("public key changed across PKCS#8 round trip")
	}
	if !keys.SameKeyPair(back, sk.Public()) {
		t.Fatal("SameKeyPair should hold for a round-tripped key")
	}
}

func TestParsePKCS8RejectsGarbage(t *testing.T) {
	if _, err := keys.ParsePKCS8([]byte("not a key")); err == nil {
		t.Fatal("expected error for non-PKCS#8 input")
	}
}

func TestExportPublicKeyPEM(t *testing.T) {
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := keys.ExportPublicKeyPEM(sk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pemBytes, []byte("BEGIN PUBLIC KEY")) {
		t.Fatalf("expected a PUBLIC KEY PEM block, got:\n%s", pemBytes)
	}
	if bytes.Contains(pemBytes, []byte("PRIVATE")) {
		t.Fatal("public key PEM must not contain private material")
	}
}
