package signing_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pkcs7"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
)

// TestGoldenCMSStructure pins the wire-level shape of a V1 signature
// (Rencana V1 §4, docs/formats.md): PAdES-B, SubFilter ETSI.CAdES.detached,
// CMS digest SHA-512, CMS signature algorithm ML-DSA-65, ML-DSA signer cert.
func TestGoldenCMSStructure(t *testing.T) {
	root, err := labpki.NewRootCA("Golden Root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := labpki.NewIntermediateCA(root, "Golden Intermediate", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, _ := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "golden"})
	csr, _, _ := enrollment.ParseAndValidateCSR(csrPEM)
	leaf, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: "golden"}, Validity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := signing.SignPDF(testpdf.Sample(), keyPEM, labpki.ChainPEM(leaf, inter.Cert), signing.Options{
		SignerName: "golden", PublicID: "sig_golden", Reason: "golden test",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if res.Algorithm != "ML-DSA-65" || res.PDFProfile != "PAdES_B" {
		t.Fatalf("result profile: %+v", res)
	}

	signed, err := pdfsign.Open(bytes.NewReader(res.SignedPDF), int64(len(res.SignedPDF)))
	if err != nil {
		t.Fatal(err)
	}
	var cms []byte
	var subFilter string
	for sig, err := range signed.Signatures() {
		if err != nil {
			t.Fatal(err)
		}
		subFilter = sig.SubFilter()
		cms = sig.Contents()
		break
	}
	if subFilter != "ETSI.CAdES.detached" {
		t.Fatalf("SubFilter = %q, want ETSI.CAdES.detached", subFilter)
	}

	p7, err := pkcs7.Parse(cms)
	if err != nil {
		t.Fatalf("parse CMS: %v", err)
	}
	if len(p7.Signers) != 1 {
		t.Fatalf("signer count = %d, want 1", len(p7.Signers))
	}
	si := p7.Signers[0]
	if !si.DigestAlgorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA512) {
		t.Fatalf("CMS digest = %s, want SHA-512", si.DigestAlgorithm.Algorithm)
	}
	if !si.DigestEncryptionAlgorithm.Algorithm.Equal(pkcs7.OIDSignatureAlgorithmMLDSA65) {
		t.Fatalf("CMS signature algorithm = %s, want ML-DSA-65", si.DigestEncryptionAlgorithm.Algorithm)
	}
	for _, c := range p7.Certificates {
		if c.PublicKeyAlgorithm != x509.MLDSA {
			t.Fatalf("embedded cert %s has non-ML-DSA key %s", c.Subject, c.PublicKeyAlgorithm)
		}
	}
}
