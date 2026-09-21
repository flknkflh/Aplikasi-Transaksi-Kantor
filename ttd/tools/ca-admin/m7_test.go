package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
)

const testPass = "a strong ceremony passphrase for tests"

func initProd(t *testing.T) Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	s := Store{Dir: dir, Passphrase: testPass, Operator: "tester"}
	if err := s.Init("Test Root CA", "Test Intermediate CA"); err != nil {
		t.Fatalf("init: %v", err)
	}
	return s
}

func TestEncryptedCAKeysRoundTrip(t *testing.T) {
	s := initProd(t)

	// keys are on disk only in encrypted form
	if _, err := os.Stat(s.path("root", "key.pem")); err == nil {
		t.Fatal("plaintext root/key.pem exists in production mode")
	}
	if _, err := os.Stat(s.path("root", "key.pem.enc")); err != nil {
		t.Fatalf("root/key.pem.enc missing: %v", err)
	}
	if !s.encrypted() {
		t.Fatal("encrypted() false")
	}

	// correct passphrase loads both CAs
	if _, err := s.Root(); err != nil {
		t.Fatalf("load root: %v", err)
	}
	if _, err := s.Intermediate(); err != nil {
		t.Fatalf("load intermediate: %v", err)
	}

	// wrong passphrase fails
	bad := Store{Dir: s.Dir, Passphrase: "nope"}
	if _, err := bad.Root(); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	// no passphrase fails at openStore
	if _, err := openStore(s.Dir, "", ""); err == nil {
		t.Fatal("openStore accepted an encrypted CA with no passphrase")
	}
}

func TestCeremonyLogIsChecksummedAppendOnly(t *testing.T) {
	s := initProd(t)
	if err := s.logCeremony("ca.init", "seed", "public/root-ca.crt.pem"); err != nil {
		t.Fatal(err)
	}
	if err := s.logCeremony("crl.publish", "n=1", "public/root-ca.crt.pem"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.path("ceremony.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1
	if lines < 2 {
		t.Fatalf("expected >=2 ceremony lines, got %d", lines)
	}
	want, _ := s.sha256File("public/root-ca.crt.pem")
	if !strings.Contains(string(raw), want) {
		t.Fatal("ceremony line does not carry the artifact SHA-256")
	}
	if !strings.Contains(string(raw), `"ca_keys_encrypted":true`) {
		t.Fatal("ceremony line does not record the encryption posture")
	}
}

// TestM7Gate is the milestone gate (§23): the CA directory's public/ must
// never hold private key material.
func TestM7Gate(t *testing.T) {
	s := initProd(t)
	if name, leak := s.hasPrivateKeyLeak(); leak {
		t.Fatalf("fresh CA leaks a private key in public/%s", name)
	}
	// plant one and confirm the gate catches it
	if err := os.WriteFile(s.path("public", "oops.pem"),
		[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, leak := s.hasPrivateKeyLeak(); !leak {
		t.Fatal("gate missed a planted private key")
	}
}

func TestBackupRestoreKeepsOriginal(t *testing.T) {
	t.Setenv("PQC_CA_PASSPHRASE", testPass)
	s := initProd(t)
	backup := filepath.Join(t.TempDir(), "b.tgz")
	if err := cmdBackup([]string{"-dir", s.Dir, "-out", backup}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if err := cmdRestore([]string{"-in", backup, "-dir", restored}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// both usable, original untouched
	if _, err := (Store{Dir: s.Dir, Passphrase: testPass}).Root(); err != nil {
		t.Fatalf("original CA broken after backup: %v", err)
	}
	if _, err := (Store{Dir: restored, Passphrase: testPass}).Root(); err != nil {
		t.Fatalf("restored CA broken: %v", err)
	}
}

func TestRevocationReasonCodeInCRL(t *testing.T) {
	s := initProd(t)
	inter, err := s.Intermediate()
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, _ := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "x"})
	csr, _, _ := enrollment.ParseAndValidateCSR(csrPEM)
	cert, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{Subject: pkixName("Dev", ""), Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	crlPEM, err := inter.NewCRLDetailed(
		[]labpki.RevokedEntry{{Serial: cert.SerialNumber, Reason: reasonCodes["keyCompromise"]}}, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Fatalf("reason code not carried: %+v", crl.RevokedCertificateEntries)
	}
}
