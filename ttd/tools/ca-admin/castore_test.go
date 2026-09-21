package main

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/core/verification"
)

// TestOfflineIssuanceAndRevocation is the M2 gate (§23): a CSR is validated,
// a device certificate is issued with an operator-assigned identity (not the
// CSR subject), a PDF signed with it verifies against the published Root CA,
// and after revocation + a fresh CRL the same PDF is reported revoked.
func TestOfflineIssuanceAndRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	s := Store{Dir: dir}
	if err := s.Init("Test Root CA", "Test Intermediate CA"); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Device side: key + CSR asking for a subject the CA must ignore.
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "attacker-chosen", Organization: "evil"})
	if err != nil {
		t.Fatal(err)
	}
	csr, _, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		t.Fatalf("validate CSR: %v", err)
	}

	inter, err := s.Intermediate()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject:  pkixName("Assigned Name", "Real Org"),
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cert.Subject.CommonName != "Assigned Name" {
		t.Fatalf("cert CN = %q, want operator-assigned %q", cert.Subject.CommonName, "Assigned Name")
	}

	rootPEM := mustRead(t, filepath.Join(dir, "public", "root-ca.crt.pem"))
	chainPEM := labpki.ChainPEM(cert, inter.Cert)

	res, err := signing.SignPDF(testpdf.Sample(), keyPEM, chainPEM, signing.Options{
		SignerName: "Assigned Name", PublicID: "sig_caadmin_test",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Before revocation: valid against the published root.
	v1, err := verification.VerifyPDF(res.SignedPDF, verification.Options{
		RootPEM: rootPEM, RequireMLDSAOnly: true,
	})
	if err != nil || !v1.Valid {
		t.Fatalf("pre-revocation verify: valid=%v err=%v", v1 != nil && v1.Valid, err)
	}

	// Revoke + publish a fresh CRL.
	l, err := s.loadLedger()
	if err != nil {
		t.Fatal(err)
	}
	l.Revocations = append(l.Revocations, Revocation{Serial: certSerialHex(cert), Reason: "test", RevokedAt: time.Now()})
	l.CRLNumber++
	crlPEM, err := inter.NewCRL([]*big.Int{cert.SerialNumber}, l.CRLNumber, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.publish(inter, crlPEM); err != nil {
		t.Fatal(err)
	}
	if err := s.saveLedger(l); err != nil {
		t.Fatal(err)
	}

	// After revocation: the CRL-aware verify must flag it.
	v2, err := verification.VerifyPDF(res.SignedPDF, verification.Options{
		RootPEM:          rootPEM,
		IntermediatePEM:  labpki.CertPEM(inter.Cert),
		CRLPEM:           mustRead(t, filepath.Join(dir, "public", "crl.pem")),
		RequireMLDSAOnly: true,
	})
	if err != nil {
		t.Fatalf("post-revocation verify: %v", err)
	}
	if v2.Valid || len(v2.Signatures) == 0 || !v2.Signatures[0].Revoked {
		t.Fatalf("expected revoked+invalid after CRL, got valid=%v revoked=%v", v2.Valid,
			len(v2.Signatures) > 0 && v2.Signatures[0].Revoked)
	}
}

func TestInitRefusesExistingDir(t *testing.T) {
	dir := t.TempDir() // already exists
	s := Store{Dir: dir}
	if err := s.Init("R", "I"); err == nil {
		t.Fatal("Init should refuse an existing directory")
	}
}

func TestShowDescribesIssuedCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	s := Store{Dir: dir}
	if err := s.Init("R", "I"); err != nil {
		t.Fatal(err)
	}
	inter, _ := s.Intermediate()
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, _ := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "x"})
	csr, _, _ := enrollment.ParseAndValidateCSR(csrPEM)
	cert, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{Subject: pkixName("Dev", ""), Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	info := certutil.Describe(cert)
	if !info.HasDocumentSigning {
		t.Fatal("issued device cert must carry the document-signing EKU")
	}
	if info.IsCA {
		t.Fatal("issued device cert must not be a CA")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
