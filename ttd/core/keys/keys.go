// Package keys generates and serialises the per-device ML-DSA-65 key pair.
//
// Security model (see Rencana V1 §5, §12): the private key is created on the
// user's device and never leaves it in plaintext. This package only turns a
// key into bytes and back; wrapping those bytes with Windows DPAPI or the
// Android Keystore is the responsibility of the platform layer. Nothing here
// writes to disk, logs key material, or performs network I/O.
package keys

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Algorithm is the single signature algorithm allowed by PQC PDF Sign V1.
const Algorithm = "ML-DSA-65"

// PEM block types used across the product.
const (
	PEMTypePrivateKey = "PRIVATE KEY" // PKCS#8
	PEMTypePublicKey  = "PUBLIC KEY"  // PKIX / SubjectPublicKeyInfo
)

// GenerateMLDSA65Key creates a fresh ML-DSA-65 private key using the crypto/rand
// backed generator in crypto/mldsa (FIPS 204).
func GenerateMLDSA65Key() (*mldsa.PrivateKey, error) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("keys: generate ML-DSA-65: %w", err)
	}
	return sk, nil
}

// MarshalPKCS8 encodes a private key as unencrypted PKCS#8 DER.
//
// The result is secret. Callers must hand it straight to the OS key-wrapping
// layer and must not persist or transmit it (Rencana V1 §5.3).
func MarshalPKCS8(sk *mldsa.PrivateKey) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("keys: nil private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal PKCS#8: %w", err)
	}
	return der, nil
}

// MarshalPKCS8PEM is MarshalPKCS8 wrapped in a "PRIVATE KEY" PEM block.
func MarshalPKCS8PEM(sk *mldsa.PrivateKey) ([]byte, error) {
	der, err := MarshalPKCS8(sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: PEMTypePrivateKey, Bytes: der}), nil
}

// ParsePKCS8 decodes a PKCS#8 private key (DER or a single PEM block) and
// verifies it is an ML-DSA-65 key. Any other algorithm is rejected so a
// classical key can never slip into the PQC-only signing path.
func ParsePKCS8(data []byte) (*mldsa.PrivateKey, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keys: parse PKCS#8: %w", err)
	}
	sk, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: expected ML-DSA private key, got %T", parsed)
	}
	if got := sk.PublicKey().Parameters(); got != mldsa.MLDSA65() {
		return nil, fmt.Errorf("keys: expected ML-DSA-65 parameter set, got %v", got)
	}
	return sk, nil
}

// ExportPublicKey returns the PKIX (SubjectPublicKeyInfo) DER encoding of the
// public half. This is safe to share and is what goes into a CSR.
func ExportPublicKey(sk *mldsa.PrivateKey) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("keys: nil private key")
	}
	der, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		return nil, fmt.Errorf("keys: marshal PKIX public key: %w", err)
	}
	return der, nil
}

// ExportPublicKeyPEM is ExportPublicKey wrapped in a "PUBLIC KEY" PEM block.
func ExportPublicKeyPEM(sk *mldsa.PrivateKey) ([]byte, error) {
	der, err := ExportPublicKey(sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: PEMTypePublicKey, Bytes: der}), nil
}

// PublicKeyFingerprint returns the hex SHA-256 of the PKIX public key encoding.
// Used to bind a CSR / certificate to the on-device key (Rencana V1 §14).
func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("keys: fingerprint: %w", err)
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum[:]), nil
}

// SameKeyPair reports whether cert's public key matches sk's public key. The
// client uses this after enrollment to confirm the issued certificate belongs
// to the key held on this device (Rencana V1 §14, acceptance §25.2).
func SameKeyPair(sk *mldsa.PrivateKey, certPub crypto.PublicKey) bool {
	pk, ok := certPub.(*mldsa.PublicKey)
	if !ok {
		return false
	}
	return sk.PublicKey().Equal(pk)
}
