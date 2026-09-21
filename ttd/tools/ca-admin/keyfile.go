package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// A production CA key is stored as key.pem.enc — the PKCS#8 PEM sealed with
// AES-256-GCM under an Argon2id key derived from PQC_CA_PASSPHRASE
// (Rencana V1 §13.2 "private key terenkripsi dengan passphrase kuat"). Lab
// mode (no passphrase) keeps key.pem in the clear with a loud warning.

const (
	encVersion   = 1
	argonTime    = 3
	argonMemKiB  = 256 * 1024 // 256 MiB — offline machine, be generous
	argonThreads = 4
	keyLen       = 32
	saltLen      = 16
)

type encBlob struct {
	Version int    `json:"version"`
	KDF     string `json:"kdf"` // "argon2id"
	Time    uint32 `json:"t"`
	MemKiB  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	CT      []byte `json:"ct"`
}

func deriveKey(pass string, salt []byte, t, m uint32, p uint8) []byte {
	return argon2.IDKey([]byte(pass), salt, t, m, p, keyLen)
}

func sealKeyPEM(pemBytes []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("ca-admin: empty passphrase")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	dk := deriveKey(passphrase, salt, argonTime, argonMemKiB, argonThreads)
	g, err := gcm(dk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	b := encBlob{
		Version: encVersion, KDF: "argon2id", Time: argonTime, MemKiB: argonMemKiB, Threads: argonThreads,
		Salt: salt, Nonce: nonce, CT: g.Seal(nil, nonce, pemBytes, nil),
	}
	return json.MarshalIndent(&b, "", "  ")
}

func openKeyPEM(blob []byte, passphrase string) ([]byte, error) {
	var b encBlob
	if err := json.Unmarshal(blob, &b); err != nil {
		return nil, fmt.Errorf("ca-admin: parse encrypted key: %w", err)
	}
	if b.Version != encVersion || b.KDF != "argon2id" {
		return nil, fmt.Errorf("ca-admin: unsupported encrypted key format")
	}
	if passphrase == "" {
		return nil, errors.New("ca-admin: this CA key is encrypted; set PQC_CA_PASSPHRASE")
	}
	dk := deriveKey(passphrase, b.Salt, b.Time, b.MemKiB, b.Threads)
	g, err := gcm(dk)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, b.Nonce, b.CT, nil)
	if err != nil {
		return nil, errors.New("ca-admin: wrong passphrase or corrupted CA key")
	}
	return pt, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}
