package verification_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/verification"
)

// TestStaleCRLWarns is the §25.5 check: verifying with a CRL whose nextUpdate
// is in the past still succeeds but surfaces a "stale" warning so the client
// can tell the user the revocation view may be out of date.
func TestStaleCRLWarns(t *testing.T) {
	fx := buildFixture(t)
	// A CRL from the SAME intermediate but with an expired nextUpdate.
	stale := buildStaleCRL(t, fx)

	res, err := verification.VerifyPDF(fx.signedPDF, verification.Options{
		RootPEM: fx.rootPEM, IntermediatePEM: fx.interPEM, CRLPEM: stale,
		RequireMLDSAOnly: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("a stale CRL must not invalidate a good signature: %+v", res.Signatures)
	}
	warned := false
	for _, w := range res.Signatures[0].Warnings {
		if strings.Contains(strings.ToLower(w), "stale") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected a stale-CRL warning, got %v", res.Signatures[0].Warnings)
	}
}

func buildStaleCRL(t *testing.T, fx fixture) []byte {
	t.Helper()
	now := time.Now()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-48 * time.Hour),
		NextUpdate: now.Add(-24 * time.Hour), // expired yesterday
	}, fx.inter.Cert, fx.inter.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// TestOversizedRejected: input past MaxPDFBytes is refused before the parser
// ever runs (Rencana V1 §24, §26).
func TestOversizedRejected(t *testing.T) {
	big := make([]byte, verification.MaxPDFBytes+1)
	copy(big, "%PDF-1.7\n")
	_, err := verification.VerifyPDF(big, verification.Options{RootPEM: []byte("x"), Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("want size-limit error, got %v", err)
	}
}

// TestMalformedNeverPanics: a spread of broken inputs all return an error
// (never a panic, never valid).
func TestMalformedNeverPanics(t *testing.T) {
	fx := buildFixture(t)
	inputs := [][]byte{
		nil,
		[]byte("%PDF-"),
		[]byte("%PDF-1.7\nnot really"),
		[]byte("\x00\x00\x00\x00"),
		[]byte(strings.Repeat("%PDF-1.7 trailer <<>> ", 500)),
		append([]byte("%PDF-1.7\n"), make([]byte, 4096)...),
	}
	for i, in := range inputs {
		res, err := verification.VerifyPDF(in, verification.Options{
			RootPEM: fx.rootPEM, RequireMLDSAOnly: true, Timeout: 3 * time.Second,
		})
		if err == nil && (res == nil || res.Valid) {
			t.Fatalf("input %d: err=nil and result missing/valid", i)
		}
	}
}
