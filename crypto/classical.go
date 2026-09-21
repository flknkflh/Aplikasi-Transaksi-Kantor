package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// ClassicalKeyPair is the classical (pre-quantum) half of a hybrid identity.
// See docs/adr/0001-fase1-spike-scope.md decision #2 for why this spike uses
// Ed25519 rather than ECDSA (PRD §1 allows either).
type ClassicalKeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func GenerateClassicalKeyPair() (*ClassicalKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate Ed25519 key: %w", err)
	}
	return &ClassicalKeyPair{Public: pub, Private: priv}, nil
}

func SignClassical(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

func VerifyClassical(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}
