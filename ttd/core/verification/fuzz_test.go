package verification_test

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/core/verification"
)

type fixture struct {
	rootPEM   []byte
	interPEM  []byte
	crlPEM    []byte
	signedPDF []byte
	inter     *labpki.CA
}

func buildFixture(tb testing.TB) fixture {
	tb.Helper()
	root, err := labpki.NewRootCA("Fuzz Root", 24*time.Hour)
	if err != nil {
		tb.Fatal(err)
	}
	inter, err := labpki.NewIntermediateCA(root, "Fuzz Intermediate", 24*time.Hour)
	if err != nil {
		tb.Fatal(err)
	}
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, _ := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "fuzz"})
	csr, _, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		tb.Fatal(err)
	}
	leaf, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: "fuzz"}, Validity: 24 * time.Hour,
	})
	if err != nil {
		tb.Fatal(err)
	}
	crl, _ := inter.NewCRL(nil, 1, 24*time.Hour)
	res, err := signing.SignPDF(testpdf.Sample(), keyPEM, labpki.ChainPEM(leaf, inter.Cert), signing.Options{
		SignerName: "fuzz", PublicID: "sig_fuzz",
	})
	if err != nil {
		tb.Fatal(err)
	}
	return fixture{
		rootPEM: labpki.CertPEM(root.Cert), interPEM: labpki.CertPEM(inter.Cert),
		crlPEM: crl, signedPDF: res.SignedPDF, inter: inter,
	}
}

// FuzzVerifyPDF throws arbitrary bytes at the PDF+CMS parser. VerifyPDF must
// never panic (recover guard) and never report valid=true for anything but
// the genuine signed PDF.
//
// NOTE: active `-fuzz` runs on this target can wedge — a crafted PDF drives
// the third-party parser (github.com/digitorus/pdf) into a CPU-bound loop;
// Options.Timeout returns an error but the parse goroutine leaks. See
// docs/security-findings.md. CI runs the seed corpus only; leave deep fuzzing
// of this target to a supervised, time-boxed manual session.
func FuzzVerifyPDF(f *testing.F) {
	fx := buildFixture(f)

	f.Add(fx.signedPDF)
	f.Add(testpdf.Sample())
	f.Add(testpdf.SampleMultipage())
	f.Add([]byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n trailer garbage"))
	f.Add([]byte("%PDF-"))
	f.Add([]byte{})
	f.Add([]byte("not a pdf at all"))
	// signed PDF with one flipped byte
	bad := append([]byte(nil), fx.signedPDF...)
	bad[len(bad)/2] ^= 0xFF
	f.Add(bad)

	f.Fuzz(func(t *testing.T, pdf []byte) {
		res, err := verification.VerifyPDF(pdf, verification.Options{
			RootPEM:          fx.rootPEM,
			IntermediatePEM:  fx.interPEM,
			CRLPEM:           fx.crlPEM,
			RequireMLDSAOnly: true,
			Timeout:          4 * time.Second,
		})
		if err != nil {
			return
		}
		if res == nil {
			t.Fatal("nil result with nil error")
		}
		if res.Valid && !bytesEqual(pdf, fx.signedPDF) {
			t.Fatalf("valid=true for input that is not the genuine signed PDF (%d bytes)", len(pdf))
		}
		// JSON form must also stay panic-free.
		_, _ = verification.VerifyPDFJSON(pdf, fx.rootPEM, fx.crlPEM)
		_, _ = verification.ListPDFSignatures(pdf)
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
