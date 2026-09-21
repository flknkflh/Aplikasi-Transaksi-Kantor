package signing_test

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
)

// FuzzSignPDF feeds arbitrary bytes as the PDF to sign, with a fixed valid
// key + chain. SignPDF must never panic (it has a recover guard); a produced
// PDF must be larger than the input (a real signature was added).
func FuzzSignPDF(f *testing.F) {
	root, err := labpki.NewRootCA("Fuzz Root", 24*time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	inter, err := labpki.NewIntermediateCA(root, "Fuzz Intermediate", 24*time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, _ := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "fuzz"})
	csr, _, _ := enrollment.ParseAndValidateCSR(csrPEM)
	leaf, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: "fuzz"}, Validity: 24 * time.Hour,
	})
	if err != nil {
		f.Fatal(err)
	}
	chainPEM := labpki.ChainPEM(leaf, inter.Cert)

	f.Add(testpdf.Sample())
	f.Add(testpdf.SampleMultipage())
	f.Add([]byte("%PDF-1.4\njunk"))
	f.Add([]byte{})
	f.Add([]byte("%PDF-1.7\n1 0 obj<<>>endobj\nxref\n0 1\n0000000000 65535 f \ntrailer<<>>\nstartxref\n9\n%%EOF"))

	f.Fuzz(func(t *testing.T, pdf []byte) {
		res, err := signing.SignPDF(pdf, keyPEM, chainPEM, signing.Options{SignerName: "fuzz", PublicID: "sig_fuzz"})
		if err != nil {
			return
		}
		if res == nil || len(res.SignedPDF) <= len(pdf) {
			t.Fatalf("SignPDF returned a non-larger PDF (%d -> %d) with no error", len(pdf), len(res.SignedPDF))
		}
		if res.Algorithm != "ML-DSA-65" || res.PDFProfile != "PAdES_B" {
			t.Fatalf("unexpected result profile: %+v", res)
		}
	})
}
