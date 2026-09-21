// Package webbridge is the narrow, browser-safe surface of core: every function
// takes and returns only []byte, string, and error, so the WebAssembly glue
// (cmd/pqcsign-wasm) is a thin syscall/js shim and everything else — including
// the behaviour the browser depends on — is testable natively. It is the
// browser sibling of mobilebridge (the upstream Android surface) and adds the
// PIN-protected key envelope (webkeys) that the browser needs and the
// desktop/Android clients get from the operating system instead.
//
// Security notes (upstream Rencana V1 §5.3 still holds):
//   - the PKCS#8 key crosses this boundary only as the return value of
//     GenerateKey/UnprotectKey and as an argument to the functions that need
//     it for ONE operation; the JavaScript caller must wipe its copy;
//   - nothing here logs, stores or transmits key material;
//   - SignPDF sets a watchdog so a hostile PDF cannot hang the worker forever
//     (upstream security finding SF-1).
package webbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/verification"
	"example.internal/pqc-pdf-sign/core/webkeys"
)

// Version identifies the bridge ABI the JavaScript side was written against.
const Version = "webbridge/1"

// SignTimeout bounds one parse+sign so a crafted PDF cannot spin forever.
const SignTimeout = 60 * time.Second

// GenerateKey creates a device ML-DSA-65 key and returns it as PKCS#8 DER.
// The caller MUST immediately wrap it (ProtectKey) and wipe this copy.
func GenerateKey() ([]byte, error) {
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return nil, err
	}
	return keys.MarshalPKCS8(sk)
}

// ExportPublicKeyPEM returns the PKIX public key (PEM) for a PKCS#8 key.
func ExportPublicKeyPEM(privateKeyPKCS8 []byte) (string, error) {
	sk, err := keys.ParsePKCS8(privateKeyPKCS8)
	if err != nil {
		return "", err
	}
	pem, err := keys.ExportPublicKeyPEM(sk)
	return string(pem), err
}

// CreateCSR builds a PEM PKCS#10 CSR proving possession of the key.
// requestJSON matches enrollment.Request.
func CreateCSR(privateKeyPKCS8 []byte, requestJSON string) (string, error) {
	pem, err := enrollment.CreateDeviceCSRFromJSON(privateKeyPKCS8, requestJSON)
	return string(pem), err
}

// CertMatchesKey reports whether the certificate's public key belongs to the
// private key. The client checks this after enrollment so a server can never
// hand it a certificate for some other key (upstream Rencana V1 §14).
func CertMatchesKey(privateKeyPKCS8 []byte, certPEM []byte) (bool, error) {
	sk, err := keys.ParsePKCS8(privateKeyPKCS8)
	if err != nil {
		return false, err
	}
	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return false, err
	}
	return keys.SameKeyPair(sk, cert.PublicKey), nil
}

// SignPDF signs pdf and returns the signed bytes plus the signing.Result as
// JSON (hashes, certificate serial/fingerprint, claimed signing time).
// optionsJSON matches signing.Options.
func SignPDF(pdf, privateKeyPKCS8, certChainPEM []byte, optionsJSON string) (signed []byte, resultJSON string, err error) {
	var o signing.Options
	if optionsJSON != "" {
		if err := json.Unmarshal([]byte(optionsJSON), &o); err != nil {
			return nil, "", fmt.Errorf("webbridge: decode options JSON: %w", err)
		}
	}
	o.Timeout = SignTimeout
	res, err := signing.SignPDF(pdf, privateKeyPKCS8, certChainPEM, o)
	if err != nil {
		return nil, "", err
	}
	out, err := json.Marshal(res)
	if err != nil {
		return nil, "", err
	}
	return res.SignedPDF, string(out), nil
}

// VerifyPDF verifies pdf against rootPEM (required) and crlPEM (optional) and
// returns the shared verification JSON (upstream docs/formats.md §5).
func VerifyPDF(pdf, rootPEM, crlPEM []byte) (string, error) {
	if len(rootPEM) == 0 {
		return "", errors.New("webbridge: a Root CA is required to verify")
	}
	return verification.VerifyPDFJSON(pdf, rootPEM, crlPEM)
}

// ProtectKey wraps the PKCS#8 key under the (mandatory) PIN.
func ProtectKey(privateKeyPKCS8 []byte, pin string) ([]byte, error) {
	return webkeys.Protect(privateKeyPKCS8, pin)
}

// UnprotectKey returns the PKCS#8 key; the caller must wipe it after one use.
func UnprotectKey(blob []byte, pin string) ([]byte, error) {
	return webkeys.Unprotect(blob, pin)
}

// ChangePIN re-wraps the blob under a new PIN without exposing the key.
func ChangePIN(blob []byte, oldPIN, newPIN string) ([]byte, error) {
	return webkeys.ChangePIN(blob, oldPIN, newPIN)
}

// PINError classifies a webkeys error for the UI: "pin_too_short",
// "wrong_pin", "corrupt", "unsupported", or "" for anything else.
func PINError(err error) string {
	switch {
	case errors.Is(err, webkeys.ErrPINTooShort):
		return "pin_too_short"
	case errors.Is(err, webkeys.ErrWrongPIN):
		return "wrong_pin"
	case errors.Is(err, webkeys.ErrCorrupt):
		return "corrupt"
	case errors.Is(err, webkeys.ErrUnsupported):
		return "unsupported"
	}
	return ""
}

// SHA512Hex returns the lowercase hex SHA-512 used throughout V1
// (hashutil.CalculateSHA512). The browser computes document hashes here rather
// than with crypto.subtle because SubtleCrypto only exists in secure contexts
// (HTTPS or localhost) and a lab server is often reached over plain HTTP.
func SHA512Hex(b []byte) string { return hashutil.CalculateSHA512(b) }

// CertFingerprint returns the hex SHA-256 fingerprint of the first certificate
// in certPEM — what a user compares out of band to pin the Root CA.
func CertFingerprint(certPEM []byte) (string, error) {
	c, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return "", err
	}
	return certutil.FingerprintSHA256(c), nil
}

// CheckDeviceCertificate enforces the V1 device-certificate profile (ML-DSA
// key, currently valid, not a CA, document-signing EKU) and returns the
// display-safe certutil.CertInfo as JSON.
func CheckDeviceCertificate(certPEM []byte) (string, error) {
	_, info, err := certutil.ParseAndValidateCertificate(certPEM, time.Now())
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(info)
	return string(out), err
}

// ListSignatures reports how many signatures a PDF already carries. The client
// refuses to sign a document twice (one document, one signature — upstream
// Rencana V1 §15.3).
func ListSignatures(pdf []byte) (int, error) {
	sigs, err := verification.ListPDFSignatures(pdf)
	return len(sigs), err
}
