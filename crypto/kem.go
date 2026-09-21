package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
)

// Hybrid KEM: X25519 + ML-KEM-768 (PRD §1: "pertukaran kunci hybrid: X25519
// atau P-256 + ML-KEM-768"). ML-KEM-768 has been in the Go standard library
// since Go 1.24 (crypto/mlkem) — and ML-DSA-65 since Go 1.27 (crypto/mldsa,
// see mldsa.go) — so the whole module needs no cgo: real, standards-track
// algorithms via the Go team's own implementation.
//
// This is a library-level demo of the combiner, not wired into any
// transport — see the ADR for why.

const hybridKEMInfo = "pqc-ledger/hybrid-kem/x25519+mlkem768/v1"

// HybridKEMKeyPair holds both halves of a recipient's hybrid KEM identity.
type HybridKEMKeyPair struct {
	X25519Private *ecdh.PrivateKey
	MLKEMPrivate  *mlkem.DecapsulationKey768
}

// HybridKEMPublicKey is the wire-format public half, safe to publish.
type HybridKEMPublicKey struct {
	X25519Public []byte
	MLKEMPublic  []byte
}

func GenerateHybridKEMKeyPair() (*HybridKEMKeyPair, error) {
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate X25519 key: %w", err)
	}
	mlkemPriv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("crypto: generate ML-KEM-768 key: %w", err)
	}
	return &HybridKEMKeyPair{X25519Private: x25519Priv, MLKEMPrivate: mlkemPriv}, nil
}

func (kp *HybridKEMKeyPair) PublicKey() HybridKEMPublicKey {
	return HybridKEMPublicKey{
		X25519Public: kp.X25519Private.PublicKey().Bytes(),
		MLKEMPublic:  kp.MLKEMPrivate.EncapsulationKey().Bytes(),
	}
}

// HybridEncapsulate is the sender side: an ephemeral X25519 ECDH with the
// recipient's classical public key, plus an ML-KEM-768 encapsulation against
// the recipient's PQC public key, combined via HKDF-SHA384 with a
// domain-separated info string. Per PRD §10 note 1 ("ML-KEM adalah mekanisme
// key encapsulation, bukan tanda tangan"), the two mechanisms are kept
// architecturally distinct and only combined at the very end.
func HybridEncapsulate(recipient HybridKEMPublicKey) (sharedKey, x25519EphemeralPublic, mlkemCiphertext []byte, err error) {
	recipientX25519Pub, err := ecdh.X25519().NewPublicKey(recipient.X25519Public)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: parse recipient X25519 public key: %w", err)
	}
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: generate ephemeral X25519 key: %w", err)
	}
	x25519Shared, err := ephemeralPriv.ECDH(recipientX25519Pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: X25519 ECDH: %w", err)
	}

	recipientMLKEMPub, err := mlkem.NewEncapsulationKey768(recipient.MLKEMPublic)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: parse recipient ML-KEM-768 public key: %w", err)
	}
	mlkemShared, ciphertext := recipientMLKEMPub.Encapsulate()

	combined, err := combineSharedSecrets(x25519Shared, mlkemShared)
	if err != nil {
		return nil, nil, nil, err
	}
	return combined, ephemeralPriv.PublicKey().Bytes(), ciphertext, nil
}

// HybridDecapsulate is the recipient side, mirroring HybridEncapsulate.
func HybridDecapsulate(kp *HybridKEMKeyPair, x25519EphemeralPublic, mlkemCiphertext []byte) ([]byte, error) {
	ephemeralPub, err := ecdh.X25519().NewPublicKey(x25519EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse ephemeral X25519 public key: %w", err)
	}
	x25519Shared, err := kp.X25519Private.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: X25519 ECDH: %w", err)
	}
	mlkemShared, err := kp.MLKEMPrivate.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: ML-KEM-768 decapsulate: %w", err)
	}
	return combineSharedSecrets(x25519Shared, mlkemShared)
}

func combineSharedSecrets(x25519Shared, mlkemShared []byte) ([]byte, error) {
	secret := make([]byte, 0, len(x25519Shared)+len(mlkemShared))
	secret = append(secret, x25519Shared...)
	secret = append(secret, mlkemShared...)

	key, err := hkdf.Key(sha512.New384, secret, nil, hybridKEMInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("crypto: HKDF combine shared secrets: %w", err)
	}
	return key, nil
}
