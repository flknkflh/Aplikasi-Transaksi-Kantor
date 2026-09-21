package mobilebridge_test

import (
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/mobilebridge"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/core/verification"
)

// TestBridgeSignVerifiesEverywhere is the §25.5 cross-platform check: a PDF
// signed through the gomobile bridge (the Android path) verifies with
// verification.VerifyPDF (the desktop/server path), and the bridge's own
// VerifyPDF agrees.
func TestBridgeSignVerifiesEverywhere(t *testing.T) {
	root, err := labpki.NewRootCA("Bridge Root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := labpki.NewIntermediateCA(root, "Bridge Intermediate", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := mobilebridge.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := mobilebridge.CreateCSR(keyDER, `{"common_name":"bridge","platform":"android"}`)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: "bridge"}, Validity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	chainPEM := labpki.ChainPEM(leaf, inter.Cert)
	rootPEM := labpki.CertPEM(root.Cert)

	opts, _ := json.Marshal(signing.Options{SignerName: "bridge", PublicID: "sig_bridge", IncludeQR: true})
	signed, err := mobilebridge.SignPDF(testpdf.Sample(), keyDER, chainPEM, string(opts))
	if err != nil {
		t.Fatalf("bridge SignPDF: %v", err)
	}

	// desktop/server verifier
	res, err := verification.VerifyPDF(signed, verification.Options{
		RootPEM: rootPEM, IntermediatePEM: labpki.CertPEM(inter.Cert), RequireMLDSAOnly: true,
	})
	if err != nil || !res.Valid {
		t.Fatalf("core VerifyPDF rejected a bridge-signed PDF: valid=%v err=%v", res != nil && res.Valid, err)
	}
	if res.Signatures[0].Algorithm != "ML-DSA-65" {
		t.Fatalf("algorithm = %q", res.Signatures[0].Algorithm)
	}

	// bridge verifier agrees
	jsonOut, err := mobilebridge.VerifyPDF(signed, rootPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	var bridgeRes verification.Result
	if err := json.Unmarshal([]byte(jsonOut), &bridgeRes); err != nil {
		t.Fatal(err)
	}
	if !bridgeRes.Valid {
		t.Fatalf("bridge VerifyPDF disagrees: %s", jsonOut)
	}
}
