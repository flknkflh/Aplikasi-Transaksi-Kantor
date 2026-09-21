package crypto

import (
	"crypto/mldsa"
	"fmt"
)

// MLDSAAlgorithm names ML-DSA-65 (FIPS 204), the post-quantum half of
// SuiteHybridEd25519MLDSA65V1. It is implemented by the Go standard library
// (crypto/mldsa, Go 1.27+), so this package needs no cgo and no external
// C library. See docs/adr/0001-fase1-spike-scope.md (addendum: the original
// liboqs choice rested on a wrong reading of the Go release notes).
const MLDSAAlgorithm = "ML-DSA-65"

// GenerateMLDSAKeyPair generates a fresh ML-DSA-65 keypair. public is the
// FIPS 204 encoded public key (1952 bytes). private is the 32-byte FIPS 204
// seed, from which the whole private key is deterministically re-derived —
// so it is small, but it is exactly as secret as a full private key. It must
// only ever be handed to a keystore for local persistence; per PRD §7 it must
// never be logged or embedded in a ledger payload, only referenced by key_id.
func GenerateMLDSAKeyPair() (public []byte, private []byte, err error) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate ML-DSA-65 keypair: %w", err)
	}
	return sk.PublicKey().Bytes(), sk.Bytes(), nil
}

// SignMLDSA signs message with the ML-DSA-65 key identified by its 32-byte
// seed (as returned by GenerateMLDSAKeyPair), using the empty context string
// ("pure" ML-DSA).
func SignMLDSA(private []byte, message []byte) ([]byte, error) {
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), private)
	if err != nil {
		return nil, fmt.Errorf("crypto: load ML-DSA-65 private key: %w", err)
	}
	sig, err := sk.Sign(nil, message, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: ML-DSA-65 sign: %w", err)
	}
	return sig, nil
}

// VerifyMLDSA reports whether sig is a valid ML-DSA-65 signature of message
// under public. A malformed public key is an error; a well-formed key with a
// signature that does not verify is (false, nil).
func VerifyMLDSA(public []byte, message, sig []byte) (bool, error) {
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), public)
	if err != nil {
		return false, fmt.Errorf("crypto: load ML-DSA-65 public key: %w", err)
	}
	if err := mldsa.Verify(pk, message, sig, nil); err != nil {
		return false, nil
	}
	return true, nil
}
