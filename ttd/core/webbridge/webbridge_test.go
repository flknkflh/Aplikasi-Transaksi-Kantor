package webbridge_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/core/verification"
	"example.internal/pqc-pdf-sign/core/webbridge"
	"example.internal/pqc-pdf-sign/core/webkeys"
)

type fixture struct {
	rootPEM, chainPEM []byte
	keyDER            []byte
}

// newFixture plays the whole enrollment: key -> CSR -> lab CA issues the
// device certificate (the role the server's online CA plays).
func newFixture(t *testing.T) fixture {
	t.Helper()
	root, err := labpki.NewRootCA("Web Root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := labpki.NewIntermediateCA(root, "Web Intermediate", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := webbridge.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := webbridge.CreateCSR(keyDER, `{"common_name":"ignored","platform":"web"}`)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, err := enrollment.ParseAndValidateCSR([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: "Browser User"}, Validity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		rootPEM:  labpki.CertPEM(root.Cert),
		chainPEM: labpki.ChainPEM(leaf, inter.Cert),
		keyDER:   keyDER,
	}
}

// The browser path: the key only ever comes back out of the PIN envelope, and
// a PDF signed with it verifies through the same strict verifier the server
// uses on submit.
func TestBrowserFlowSignThroughPINEnvelopeVerifiesStrictly(t *testing.T) {
	f := newFixture(t)

	blob, err := webbridge.ProtectKey(f.keyDER, "246810")
	if err != nil {
		t.Fatalf("ProtectKey: %v", err)
	}
	unwrapped, err := webbridge.UnprotectKey(blob, "246810")
	if err != nil {
		t.Fatalf("UnprotectKey: %v", err)
	}

	ok, err := webbridge.CertMatchesKey(unwrapped, f.chainPEM)
	if err != nil || !ok {
		t.Fatalf("issued certificate must match the unwrapped key: ok=%v err=%v", ok, err)
	}

	opts, _ := json.Marshal(signing.Options{SignerName: "Browser User", PublicID: "sig_web1", Reason: "test"})
	signed, resultJSON, err := webbridge.SignPDF(testpdf.Sample(), unwrapped, f.chainPEM, string(opts))
	if err != nil {
		t.Fatalf("SignPDF: %v", err)
	}
	var sr signing.Result
	if err := json.Unmarshal([]byte(resultJSON), &sr); err != nil {
		t.Fatalf("result JSON: %v", err)
	}
	if sr.Algorithm != "ML-DSA-65" || sr.PublicID != "sig_web1" || sr.SignedSHA512 == "" || sr.CertificateSerial == "" {
		t.Fatalf("unexpected sign result: %+v", sr)
	}

	out, err := webbridge.VerifyPDF(signed, f.rootPEM, nil)
	if err != nil {
		t.Fatalf("VerifyPDF: %v", err)
	}
	var vr verification.Result
	if err := json.Unmarshal([]byte(out), &vr); err != nil || !vr.Valid {
		t.Fatalf("bridge verifier rejected a bridge-signed PDF: err=%v %s", err, out)
	}
}

func TestTamperedPDFAndWrongRootAreRejected(t *testing.T) {
	f := newFixture(t)
	signed, _, err := webbridge.SignPDF(testpdf.Sample(), f.keyDER, f.chainPEM, `{"public_id":"sig_x"}`)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), signed...)
	i := bytes.Index(tampered, []byte("%PDF-"))
	if i < 0 {
		t.Fatal("no PDF header")
	}
	// Flip a byte inside the signed range (well before the signature blob).
	tampered[i+200] ^= 0xFF
	if out, err := webbridge.VerifyPDF(tampered, f.rootPEM, nil); err == nil {
		var vr verification.Result
		_ = json.Unmarshal([]byte(out), &vr)
		if vr.Valid {
			t.Fatal("a tampered PDF must not verify")
		}
	}

	otherRoot, _ := labpki.NewRootCA("Someone Else", time.Hour)
	out, err := webbridge.VerifyPDF(signed, labpki.CertPEM(otherRoot.Cert), nil)
	if err == nil {
		var vr verification.Result
		_ = json.Unmarshal([]byte(out), &vr)
		if vr.Valid {
			t.Fatal("verification against an unrelated Root CA must fail")
		}
	}
}

func TestVerifyRequiresARootCA(t *testing.T) {
	if _, err := webbridge.VerifyPDF(testpdf.Sample(), nil, nil); err == nil {
		t.Fatal("verification without an explicit Root CA must be refused")
	}
}

func TestPINEnvelopeErrorsAreClassifiedForTheUI(t *testing.T) {
	f := newFixture(t)
	if _, err := webbridge.ProtectKey(f.keyDER, "123"); webbridge.PINError(err) != "pin_too_short" {
		t.Fatalf("want pin_too_short, got %q (%v)", webbridge.PINError(err), err)
	}
	blob, err := webbridge.ProtectKey(f.keyDER, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := webbridge.UnprotectKey(blob, "000000"); webbridge.PINError(err) != "wrong_pin" {
		t.Fatalf("want wrong_pin, got %q", webbridge.PINError(err))
	}
	if _, err := webbridge.UnprotectKey([]byte("{}"), "123456"); webbridge.PINError(err) != "unsupported" {
		t.Fatalf("want unsupported, got %q", webbridge.PINError(err))
	}
	if webbridge.PINError(errors.New("boom")) != "" {
		t.Fatal("unrelated errors must not be classified")
	}
	if !errors.Is(webkeys.ErrWrongPIN, webkeys.ErrWrongPIN) {
		t.Fatal("sanity")
	}
}

func TestCertMatchesKeyRejectsAnotherDevicesKey(t *testing.T) {
	a, b := newFixture(t), newFixture(t)
	ok, err := webbridge.CertMatchesKey(b.keyDER, a.chainPEM)
	if err != nil || ok {
		t.Fatalf("a certificate must not match another device's key: ok=%v err=%v", ok, err)
	}
}

func TestExportPublicKeyAndCSRDoNotLeakThePrivateKey(t *testing.T) {
	f := newFixture(t)
	pub, err := webbridge.ExportPublicKeyPEM(f.keyDER)
	if err != nil || !strings.Contains(pub, "PUBLIC KEY") {
		t.Fatalf("public key: %v %q", err, pub)
	}
	csr, err := webbridge.CreateCSR(f.keyDER, `{"common_name":"x"}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(csr, "PRIVATE KEY") || strings.Contains(pub, "PRIVATE KEY") {
		t.Fatal("private key material must never appear in exported artefacts")
	}
}

func TestSignRejectsBadOptionsAndGarbagePDF(t *testing.T) {
	f := newFixture(t)
	if _, _, err := webbridge.SignPDF(testpdf.Sample(), f.keyDER, f.chainPEM, "{not json"); err == nil {
		t.Fatal("bad options JSON must be refused")
	}
	if _, _, err := webbridge.SignPDF([]byte("this is not a pdf"), f.keyDER, f.chainPEM, ""); err == nil {
		t.Fatal("a non-PDF must be refused")
	}
}
