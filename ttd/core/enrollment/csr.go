// Package enrollment builds and inspects device certificate signing requests.
//
// The client sends a CSR (public key + proof of possession), never a private
// key (Rencana V1 §1, §13.5). The subject a client asks for is advisory only;
// the real identity is assigned by the server/CA from the verified account.
package enrollment

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"example.internal/pqc-pdf-sign/core/keys"
)

// PEMTypeCSR is the PEM block type for a PKCS#10 request.
const PEMTypeCSR = "CERTIFICATE REQUEST"

// Request is the client-supplied context for a CSR. Only CommonName /
// Organization / OrganizationalUnit reach the PKCS#10 subject; the rest are
// carried alongside the request as enrollment metadata for the server.
type Request struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`

	// Enrollment metadata (not part of the CSR subject).
	AccountLabel string `json:"account_label,omitempty"`
	DeviceLabel  string `json:"device_label,omitempty"`
	Platform     string `json:"platform,omitempty"` // "windows" | "android"
}

// CreateDeviceCSR signs a PKCS#10 request with the device's own ML-DSA-65 key,
// proving possession. Input is the PKCS#8 private key bytes from the OS
// key-wrapping layer; output is a PEM CSR ready to POST to the server.
func CreateDeviceCSR(privateKeyPKCS8 []byte, req Request) ([]byte, error) {
	sk, err := keys.ParsePKCS8(privateKeyPKCS8)
	if err != nil {
		return nil, err
	}
	if req.CommonName == "" {
		return nil, errors.New("enrollment: CommonName is required")
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: req.CommonName},
	}
	if req.Organization != "" {
		tmpl.Subject.Organization = []string{req.Organization}
	}
	if req.OrganizationalUnit != "" {
		tmpl.Subject.OrganizationalUnit = []string{req.OrganizationalUnit}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, sk)
	if err != nil {
		return nil, fmt.Errorf("enrollment: create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: PEMTypeCSR, Bytes: der}), nil
}

// CreateDeviceCSRFromJSON is the gomobile-friendly form: the request is a JSON
// object matching Request.
func CreateDeviceCSRFromJSON(privateKeyPKCS8 []byte, requestJSON string) ([]byte, error) {
	var req Request
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return nil, fmt.Errorf("enrollment: decode request JSON: %w", err)
	}
	return CreateDeviceCSR(privateKeyPKCS8, req)
}

// CSRInfo summarises a validated CSR for the server's enrollment record.
type CSRInfo struct {
	Subject            string `json:"subject"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKeyFP        string `json:"public_key_fingerprint_sha256"`
	ProofOfPossession  bool   `json:"proof_of_possession"`
}

// ParseAndValidateCSR performs the server-side checks from Rencana V1 §13.5:
// the request parses, its self-signature (proof of possession) verifies, and
// the public key is ML-DSA-65. It deliberately does not trust the subject.
func ParseAndValidateCSR(csrPEM []byte) (*x509.CertificateRequest, *CSRInfo, error) {
	der := csrPEM
	if block, _ := pem.Decode(csrPEM); block != nil {
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("enrollment: CSR proof-of-possession failed: %w", err)
	}
	pub, ok := csr.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("enrollment: CSR public key must be ML-DSA, got %s", csr.PublicKeyAlgorithm)
	}
	if pub.Parameters() != mldsa.MLDSA65() {
		return nil, nil, fmt.Errorf("enrollment: CSR public key must be ML-DSA-65, got %s", pub.Parameters())
	}
	fp, err := keys.PublicKeyFingerprint(pub)
	if err != nil {
		return nil, nil, err
	}
	return csr, &CSRInfo{
		Subject:            csr.Subject.String(),
		PublicKeyAlgorithm: keys.Algorithm,
		PublicKeyFP:        fp,
		ProofOfPossession:  true,
	}, nil
}
