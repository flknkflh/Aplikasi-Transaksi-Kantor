// Package hashutil centralises the document hash used throughout V1.
//
// V1 uses SHA-512 everywhere: the CMS/PDF digest on the ML-DSA path
// (RFC 9882) and the document hashes recorded by client and server
// (Rencana V1 §4, §18.2).
package hashutil

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// CalculateSHA512 returns the lowercase hex SHA-512 of b.
func CalculateSHA512(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

// CalculateSHA512Reader streams r through SHA-512 without buffering it all.
func CalculateSHA512Reader(r io.Reader) (string, error) {
	h := sha512.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
