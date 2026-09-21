package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
)

// Store is the on-disk layout of a CA directory.
//
//	<dir>/
//	  root/key.pem[.enc]  root/cert.pem
//	  intermediate/key.pem[.enc]  intermediate/cert.pem
//	  public/  root-ca.crt.pem  intermediate-ca.crt.pem  ca-chain.pem  crl.pem
//	  ledger.json       { crl_number, revocations[] }
//	  issued.jsonl      one line per issued device certificate
//	  ceremony.jsonl    append-only audit log with artifact checksums
//
// With PQC_CA_PASSPHRASE set, CA private keys are written as key.pem.enc
// (Argon2id + AES-256-GCM, Rencana V1 §13.2). Without it, key.pem is written
// in the clear — lab only.
type Store struct {
	Dir        string
	Passphrase string // "" -> lab mode (unencrypted keys)
	Operator   string // recorded in the ceremony log
}

type Ledger struct {
	CRLNumber   int64        `json:"crl_number"`
	Revocations []Revocation `json:"revocations"`
}

type Revocation struct {
	Serial     string    `json:"serial"` // hex
	Reason     string    `json:"reason"`
	ReasonCode int       `json:"reason_code"` // RFC 5280 (x509.RevocationReason*)
	RevokedAt  time.Time `json:"revoked_at"`
}

// CeremonyEntry is one append-only audit line (Rencana V1 §13.2 "checksum
// output", §23 M7 "audit ceremony").
type CeremonyEntry struct {
	At        time.Time         `json:"at"`
	Action    string            `json:"action"`
	Operator  string            `json:"operator"`
	Encrypted bool              `json:"ca_keys_encrypted"`
	Artifacts map[string]string `json:"artifacts"` // relative path -> sha256 hex
	Note      string            `json:"note,omitempty"`
}

type IssuedRecord struct {
	Serial      string    `json:"serial"`
	Subject     string    `json:"subject"`
	Account     string    `json:"account"`
	DeviceLabel string    `json:"device_label"`
	Fingerprint string    `json:"fingerprint_sha256"`
	NotAfter    time.Time `json:"not_after"`
	IssuedAt    time.Time `json:"issued_at"`
	CSRFP       string    `json:"csr_public_key_fingerprint"`
}

func (s Store) path(parts ...string) string {
	return filepath.Join(append([]string{s.Dir}, parts...)...)
}

func (s Store) exists() bool {
	_, err := os.Stat(s.path("intermediate", "cert.pem"))
	return err == nil
}

// encrypted reports whether the CA keys on disk are in encrypted form.
func (s Store) encrypted() bool {
	_, err := os.Stat(s.path("intermediate", "key.pem.enc"))
	return err == nil
}

// Init creates a fresh Root + Intermediate CA under s.Dir.
func (s Store) Init(rootCN, interCN string) error {
	if _, err := os.Stat(s.Dir); err == nil {
		return fmt.Errorf("ca-admin: %s already exists; refusing to overwrite", s.Dir)
	}
	root, err := labpki.NewRootCA(rootCN, 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	inter, err := labpki.NewIntermediateCA(root, interCN, 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	for _, d := range []string{"root", "intermediate", "public"} {
		if err := os.MkdirAll(s.path(d), 0o700); err != nil {
			return err
		}
	}
	if err := s.writeCA("root", root); err != nil {
		return err
	}
	if err := s.writeCA("intermediate", inter); err != nil {
		return err
	}
	if err := s.publish(inter, nil); err != nil {
		return err
	}
	return s.saveLedger(&Ledger{})
}

func (s Store) writeCA(name string, ca *labpki.CA) error {
	keyPEM, err := keys.MarshalPKCS8PEM(ca.Key)
	if err != nil {
		return err
	}
	if s.Passphrase != "" {
		sealed, err := sealKeyPEM(keyPEM, s.Passphrase)
		if err != nil {
			return err
		}
		if err := os.WriteFile(s.path(name, "key.pem.enc"), sealed, 0o600); err != nil {
			return err
		}
	} else {
		if err := os.WriteFile(s.path(name, "key.pem"), keyPEM, 0o600); err != nil {
			return err
		}
	}
	return os.WriteFile(s.path(name, "cert.pem"), labpki.CertPEM(ca.Cert), 0o644)
}

func (s Store) loadCA(name string) (*labpki.CA, error) {
	var keyPEM []byte
	if enc, err := os.ReadFile(s.path(name, "key.pem.enc")); err == nil {
		keyPEM, err = openKeyPEM(enc, s.Passphrase)
		if err != nil {
			return nil, err
		}
	} else {
		keyPEM, err = os.ReadFile(s.path(name, "key.pem"))
		if err != nil {
			return nil, fmt.Errorf("ca-admin: no CA key for %q: %w", name, err)
		}
	}
	sk, err := keys.ParsePKCS8(keyPEM)
	if err != nil {
		return nil, err
	}
	certRaw, err := os.ReadFile(s.path(name, "cert.pem"))
	if err != nil {
		return nil, err
	}
	cert, err := certutil.ParseCertificatePEM(certRaw)
	if err != nil {
		return nil, err
	}
	return &labpki.CA{Key: sk, Cert: cert}, nil
}

// Intermediate is the signing CA for device certs and CRLs.
func (s Store) Intermediate() (*labpki.CA, error) { return s.loadCA("intermediate") }
func (s Store) Root() (*labpki.CA, error)         { return s.loadCA("root") }

func (s Store) loadLedger() (*Ledger, error) {
	raw, err := os.ReadFile(s.path("ledger.json"))
	if err != nil {
		return nil, err
	}
	var l Ledger
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s Store) saveLedger(l *Ledger) error {
	raw, _ := json.MarshalIndent(l, "", "  ")
	return os.WriteFile(s.path("ledger.json"), raw, 0o644)
}

func (s Store) appendIssued(r IssuedRecord) error {
	f, err := os.OpenFile(s.path("issued.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(r)
	_, err = f.Write(append(line, '\n'))
	return err
}

// publish (re)writes the public trust material. crlPEM may be nil.
func (s Store) publish(inter *labpki.CA, crlPEM []byte) error {
	root, err := s.Root()
	if err != nil {
		return err
	}
	writes := map[string][]byte{
		"root-ca.crt.pem":         labpki.CertPEM(root.Cert),
		"intermediate-ca.crt.pem": labpki.CertPEM(inter.Cert),
		"ca-chain.pem":            labpki.ChainPEM(inter.Cert, root.Cert),
	}
	if crlPEM != nil {
		writes["crl.pem"] = crlPEM
	}
	for name, b := range writes {
		if err := os.WriteFile(s.path("public", name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

var errNotInitialised = errors.New("ca-admin: CA directory not initialised (run `ca-admin init` first)")

func openStore(dir, passphrase, operator string) (Store, error) {
	s := Store{Dir: dir, Passphrase: passphrase, Operator: operator}
	if !s.exists() {
		return s, errNotInitialised
	}
	if s.encrypted() && s.Passphrase == "" {
		return s, errors.New("ca-admin: CA keys are encrypted; set PQC_CA_PASSPHRASE")
	}
	return s, nil
}

func sha256Bytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// sha256File returns the hex SHA-256 of a file under the CA directory.
func (s Store) sha256File(rel string) (string, error) {
	b, err := os.ReadFile(s.path(rel))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:]), nil
}

// logCeremony appends one audit line covering the given artifact paths
// (relative to the CA dir), each with its current SHA-256.
func (s Store) logCeremony(action, note string, artifacts ...string) error {
	e := CeremonyEntry{
		At: time.Now().UTC(), Action: action, Operator: s.Operator,
		Encrypted: s.encrypted(), Artifacts: map[string]string{}, Note: note,
	}
	for _, a := range artifacts {
		if sum, err := s.sha256File(a); err == nil {
			e.Artifacts[filepath.ToSlash(a)] = sum
		}
	}
	f, err := os.OpenFile(s.path("ceremony.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(&e)
	_, err = f.Write(append(line, '\n'))
	return err
}

// hasPrivateKeyLeak scans the public directory for anything that looks like a
// private key (the M7 gate, Rencana V1 §23).
func (s Store) hasPrivateKeyLeak() (string, bool) {
	entries, _ := os.ReadDir(s.path("public"))
	for _, e := range entries {
		b, err := os.ReadFile(s.path("public", e.Name()))
		if err != nil {
			continue
		}
		if bytesContainsAny(b, "PRIVATE KEY", "BEGIN EC PRIVATE", "BEGIN RSA PRIVATE") {
			return e.Name(), true
		}
	}
	return "", false
}

func bytesContainsAny(b []byte, subs ...string) bool {
	s := strings.ToUpper(string(b))
	for _, x := range subs {
		if strings.Contains(s, strings.ToUpper(x)) {
			return true
		}
	}
	return false
}

// certSerialHex renders a certificate serial the way `revoke` expects it.
func certSerialHex(c *x509.Certificate) string { return fmt.Sprintf("%x", c.SerialNumber) }
