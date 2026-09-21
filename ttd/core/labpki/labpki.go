// Package labpki builds a throwaway ML-DSA-65 CA hierarchy for the lab.
//
// LAB / TEST ONLY. This is not the production PKI ceremony. Real Root and
// Intermediate keys are generated offline with OpenSSL and never touch a
// server or an application build (Rencana V1 §13, §28). Nothing here is safe
// to ship: keys live in memory and are written unencrypted where the caller
// asks. Use it to produce fixtures for the M1 spike and core tests.
package labpki

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/keys"
)

// CA is an in-memory certificate authority.
type CA struct {
	Key  *mldsa.PrivateKey
	Cert *x509.Certificate
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewRootCA creates a self-signed ML-DSA-65 root (basicConstraints CA:TRUE,
// pathlen:1; keyUsage keyCertSign,cRLSign), mirroring the OpenSSL template in
// Rencana V1 §13.2.
func NewRootCA(commonName string, validity time.Duration) (*CA, error) {
	key, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, OrganizationalUnit: []string{"PQC Root CA"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	cert, err := selfSign(tmpl, key)
	if err != nil {
		return nil, err
	}
	return &CA{Key: key, Cert: cert}, nil
}

// NewIntermediateCA issues an ML-DSA-65 intermediate under parent
// (CA:TRUE, pathlen:0), the device-signing CA of Rencana V1 §13.3.
func NewIntermediateCA(parent *CA, commonName string, validity time.Duration) (*CA, error) {
	if parent == nil {
		return nil, errors.New("labpki: nil parent CA")
	}
	key, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, OrganizationalUnit: []string{"PQC Device Signing CA"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, key.Public(), parent.Key)
	if err != nil {
		return nil, fmt.Errorf("labpki: create intermediate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Key: key, Cert: cert}, nil
}

// DeviceCertOptions controls a single device certificate.
type DeviceCertOptions struct {
	Subject   pkix.Name
	Validity  time.Duration
	CRLURL    string // CRL distribution point, optional
	NotBefore time.Time
}

// IssueDeviceCert signs a leaf certificate for the ML-DSA-65 public key in csr.
// The subject is taken from opts, not from the CSR (Rencana V1 §13.5). The
// leaf gets keyUsage digitalSignature and the id-kp-documentSigning EKU that
// digitorus/pdfsign requires.
func (ca *CA) IssueDeviceCert(csr *x509.CertificateRequest, opts DeviceCertOptions) (*x509.Certificate, error) {
	if csr == nil {
		return nil, errors.New("labpki: nil CSR")
	}
	if _, ok := csr.PublicKey.(*mldsa.PublicKey); !ok {
		return nil, fmt.Errorf("labpki: CSR public key must be ML-DSA, got %s", csr.PublicKeyAlgorithm)
	}
	if opts.Validity == 0 {
		opts.Validity = 365 * 24 * time.Hour
	}
	nb := opts.NotBefore
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               opts.Subject,
		NotBefore:             nb,
		NotAfter:              nb.Add(opts.Validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{certutil.OIDDocumentSigningEKU},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if opts.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{opts.CRLURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("labpki: issue device cert: %w", err)
	}
	return x509.ParseCertificate(der)
}

// NewCRL issues a CRL signed by this CA listing the given serials as revoked.
func (ca *CA) NewCRL(revokedSerials []*big.Int, number int64, validity time.Duration) ([]byte, error) {
	entries := make([]RevokedEntry, len(revokedSerials))
	for i, s := range revokedSerials {
		entries[i] = RevokedEntry{Serial: s}
	}
	return ca.NewCRLDetailed(entries, number, validity)
}

// RevokedEntry is one CRL entry with an optional RFC 5280 reason code
// (x509.RevocationReason*, e.g. x509.KeyCompromise).
type RevokedEntry struct {
	Serial *big.Int
	Reason int
	At     time.Time
}

// NewCRLDetailed issues a CRL with per-entry revocation times and reason codes.
func (ca *CA) NewCRLDetailed(entries []RevokedEntry, number int64, validity time.Duration) ([]byte, error) {
	if validity == 0 {
		validity = 7 * 24 * time.Hour
	}
	now := time.Now()
	rl := make([]x509.RevocationListEntry, 0, len(entries))
	for _, e := range entries {
		at := e.At
		if at.IsZero() {
			at = now
		}
		rl = append(rl, x509.RevocationListEntry{SerialNumber: e.Serial, RevocationTime: at, ReasonCode: e.Reason})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                now.Add(validity),
		RevokedCertificateEntries: rl,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("labpki: create CRL: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// CertPEM encodes a certificate as a PEM block.
func CertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// ChainPEM concatenates certificates into one PEM bundle, in argument order.
func ChainPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, CertPEM(c)...)
	}
	return out
}

func selfSign(tmpl *x509.Certificate, key *mldsa.PrivateKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("labpki: self-sign: %w", err)
	}
	return x509.ParseCertificate(der)
}
