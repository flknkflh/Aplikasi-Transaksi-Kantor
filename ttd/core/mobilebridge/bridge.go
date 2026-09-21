// Package mobilebridge is the narrow, gomobile-safe surface for the Android
// AAR (Rencana V1 §10.2). Every function takes and returns only []byte,
// string, and error — no Go structs cross the binding. The Windows client
// uses the core packages directly; this package exists so both platforms
// share exactly one implementation.
package mobilebridge

import (
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/verification"
)

// GenerateKey creates a device ML-DSA-65 key and returns it as PKCS#8 DER.
// The caller MUST immediately wrap the result with the Android Keystore
// (Rencana V1 §12.2) and must never log or upload it.
func GenerateKey() ([]byte, error) {
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return nil, err
	}
	return keys.MarshalPKCS8(sk)
}

// ExportPublicKey returns the PKIX public key PEM for a wrapped PKCS#8 key.
func ExportPublicKey(privateKeyPKCS8 []byte) ([]byte, error) {
	sk, err := keys.ParsePKCS8(privateKeyPKCS8)
	if err != nil {
		return nil, err
	}
	return keys.ExportPublicKeyPEM(sk)
}

// CreateCSR builds a PEM CSR. requestJSON matches enrollment.Request.
func CreateCSR(privateKeyPKCS8 []byte, requestJSON string) ([]byte, error) {
	return enrollment.CreateDeviceCSRFromJSON(privateKeyPKCS8, requestJSON)
}

// SignPDF signs pdf and returns the signed PDF bytes. optionsJSON matches
// signing.Options.
func SignPDF(pdf, privateKeyPKCS8, certChainPEM []byte, optionsJSON string) ([]byte, error) {
	return signing.SignPDFFromJSON(pdf, privateKeyPKCS8, certChainPEM, optionsJSON)
}

// VerifyPDF verifies pdf against rootPEM (required) and crlPEM (optional) and
// returns the shared verification JSON. crlPEM may be nil.
func VerifyPDF(pdf, rootPEM, crlPEM []byte) (string, error) {
	return verification.VerifyPDFJSON(pdf, rootPEM, crlPEM)
}
