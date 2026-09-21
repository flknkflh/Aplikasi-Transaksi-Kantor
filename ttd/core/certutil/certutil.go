// Package certutil parses and validates X.509 material for PQC PDF Sign V1.
//
// All trust decisions are made against an explicitly supplied Root CA. A root
// carried inside a PDF or a certificate chain is never treated as a trust
// anchor (Rencana V1 §5.3, §16).
package certutil

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// OIDDocumentSigningEKU is id-kp-documentSigning (1.3.6.1.5.5.7.3.36), the
// extended key usage digitorus/pdfsign requires on a PDF signer certificate.
var OIDDocumentSigningEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

// CertInfo is a display-safe summary of a certificate.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"` // hex, no separators
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsCA               bool      `json:"is_ca"`
	HasDocumentSigning bool      `json:"has_document_signing_eku"`
}

// ParseCertificatePEM decodes the first CERTIFICATE block in pemBytes.
func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("certutil: no CERTIFICATE block found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		pemBytes = rest
	}
}

// ParseChainPEM decodes every CERTIFICATE block, in file order. For a device
// bundle the convention is leaf first, then intermediates, optionally the root.
func ParseChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certutil: parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("certutil: chain contains no certificates")
	}
	return out, nil
}

// FingerprintSHA256 returns the hex SHA-256 of the certificate DER.
func FingerprintSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return fmt.Sprintf("%x", sum[:])
}

// HasDocumentSigningEKU reports whether c carries id-kp-documentSigning.
func HasDocumentSigningEKU(c *x509.Certificate) bool {
	for _, oid := range c.UnknownExtKeyUsage {
		if oid.Equal(OIDDocumentSigningEKU) {
			return true
		}
	}
	return false
}

// Describe builds a CertInfo for display / logging (never includes key bytes).
func Describe(c *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       fmt.Sprintf("%x", c.SerialNumber),
		FingerprintSHA256:  FingerprintSHA256(c),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		IsCA:               c.IsCA,
		HasDocumentSigning: HasDocumentSigningEKU(c),
	}
}

// IsMLDSA reports whether the certificate's public key is ML-DSA.
func IsMLDSA(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*mldsa.PublicKey)
	return ok
}

// ParseAndValidateCertificate parses a leaf certificate and enforces the V1
// device-certificate profile: ML-DSA public key, currently within validity,
// not a CA, and carrying the document-signing EKU.
func ParseAndValidateCertificate(pemBytes []byte, at time.Time) (*x509.Certificate, *CertInfo, error) {
	c, err := ParseCertificatePEM(pemBytes)
	if err != nil {
		return nil, nil, err
	}
	if !IsMLDSA(c) {
		return nil, nil, fmt.Errorf("certutil: device certificate must be ML-DSA, got %s", c.PublicKeyAlgorithm)
	}
	if at.Before(c.NotBefore) || at.After(c.NotAfter) {
		return nil, nil, fmt.Errorf("certutil: certificate not valid at %s (validity %s..%s)",
			at.Format(time.RFC3339), c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
	}
	if c.IsCA {
		return nil, nil, errors.New("certutil: device certificate must not be a CA")
	}
	if !HasDocumentSigningEKU(c) {
		return nil, nil, errors.New("certutil: device certificate is missing id-kp-documentSigning EKU (1.3.6.1.5.5.7.3.36)")
	}
	info := Describe(c)
	return c, &info, nil
}

// ChainResult is the outcome of a chain build.
type ChainResult struct {
	Chains       [][]*x509.Certificate
	TrustedChain bool
	Error        error
}

// ValidateCertificateChain verifies leaf against an explicit root pool. The
// caller supplies roots and any intermediates as PEM; intermediates found in
// the leaf bundle are added automatically. EKU checking is intentionally
// permissive here (KeyUsageAny) because the document-signing EKU is
// non-standard; ParseAndValidateCertificate covers the profile check.
func ValidateCertificateChain(leaf *x509.Certificate, intermediates []*x509.Certificate, rootPEM []byte, at time.Time) ChainResult {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return ChainResult{Error: errors.New("certutil: no valid certificates in root PEM")}
	}
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		if c.Equal(leaf) {
			continue
		}
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return ChainResult{Error: err}
	}
	return ChainResult{Chains: chains, TrustedChain: len(chains) > 0}
}

// CRLStatus is the result of checking a certificate against a CRL.
type CRLStatus struct {
	Checked     bool      `json:"checked"`
	Revoked     bool      `json:"revoked"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
	ThisUpdate  time.Time `json:"this_update,omitempty"`
	NextUpdate  time.Time `json:"next_update,omitempty"`
	Stale       bool      `json:"stale"` // now is past NextUpdate
	SignatureOK bool      `json:"signature_ok"`
}

// ValidateCRL parses a PEM/DER CRL, verifies it was signed by issuer, checks
// freshness, and reports whether target's serial is listed as revoked.
// This is the offline revocation path for V1 verification (Rencana V1 §16.1).
func ValidateCRL(crlBytes []byte, issuer, target *x509.Certificate, now time.Time) (CRLStatus, error) {
	der := crlBytes
	if block, _ := pem.Decode(crlBytes); block != nil {
		der = block.Bytes
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return CRLStatus{}, fmt.Errorf("certutil: parse CRL: %w", err)
	}
	st := CRLStatus{
		Checked:    true,
		ThisUpdate: crl.ThisUpdate,
		NextUpdate: crl.NextUpdate,
		Stale:      !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate),
	}
	if issuer != nil {
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return st, fmt.Errorf("certutil: CRL not signed by expected issuer: %w", err)
		}
		st.SignatureOK = true
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if serialEqual(entry.SerialNumber, target.SerialNumber) {
			st.Revoked = true
			st.RevokedAt = entry.RevocationTime
			break
		}
	}
	return st, nil
}

func serialEqual(a, b *big.Int) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Cmp(b) == 0
}
