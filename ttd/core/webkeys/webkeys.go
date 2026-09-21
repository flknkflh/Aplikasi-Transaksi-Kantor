// Package webkeys protects the device ML-DSA-65 private key for storage in a
// browser. It is the browser counterpart of the desktop client's DPAPI
// envelope (apps/windows/internal/keystore/envelope.go in the upstream repo):
//
//	ML-DSA-65 PKCS#8
//	  -> AES-256-GCM(wrapKey)            key ciphertext
//	random 32-byte wrapKey
//	  -> AES-256-GCM(Argon2id(PIN))      wrapped wrapKey
//
// The OS-binding layer (DPAPI on Windows) has no browser equivalent, so it is
// deliberately NOT modelled here: the web client adds it on the JavaScript
// side by encrypting the blob this package returns with a non-extractable
// WebCrypto AES-GCM key kept in IndexedDB. This package therefore only does
// the part that can be tested natively and is identical on every platform: the
// PIN is MANDATORY (a browser profile has no other user-presence check), the
// KDF is Argon2id, and every parameter read back from a stored blob is bounded
// so a crafted blob cannot make Unprotect allocate gigabytes.
//
// Nothing here logs or returns secret material except through the documented
// return values, and intermediate secrets are wiped before returning.
package webkeys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// MinPINLength is the shortest PIN (in characters) Protect accepts.
const MinPINLength = 6

const (
	blobFormat  = "pqc-webkey"
	blobVersion = 1

	wrapKeyLen = 32
	saltLen    = 16

	// Bounds applied to KDF parameters read from a stored blob.
	maxKDFTime    = 10
	maxKDFMemKiB  = 256 * 1024 // 256 MiB
	maxKDFThreads = 16
	minKDFMemKiB  = 8 // argon2 requires memory >= 8*threads; checked below too
)

// Sentinel errors. ErrWrongPIN is returned both for a wrong PIN and for a
// wrapped-key ciphertext that fails authentication: the two are
// cryptographically indistinguishable.
var (
	ErrPINTooShort = fmt.Errorf("webkeys: PIN must be at least %d characters", MinPINLength)
	ErrWrongPIN    = errors.New("webkeys: wrong PIN")
	ErrCorrupt     = errors.New("webkeys: key blob is corrupt or tampered")
	ErrUnsupported = errors.New("webkeys: unsupported key blob")
)

// KDF holds the Argon2id parameters recorded in a blob.
type KDF struct {
	Name    string `json:"name"` // "argon2id"
	Time    uint32 `json:"t"`
	MemKiB  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
}

// DefaultKDF matches the desktop client's parameters (t=3, 64 MiB, p=4).
var DefaultKDF = KDF{Name: "argon2id", Time: 3, MemKiB: 64 * 1024, Threads: 4}

type blob struct {
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	KDF       KDF       `json:"kdf"`
	WrapNonce []byte    `json:"wrap_nonce"` // AES-GCM nonce over wrapKey
	WrapCT    []byte    `json:"wrap_ct"`    // AES-GCM(Argon2id(PIN), wrapKey)
	KeyNonce  []byte    `json:"key_nonce"`  // AES-GCM nonce over the PKCS#8
	KeyCT     []byte    `json:"key_ct"`     // AES-GCM(wrapKey, pkcs8)
}

// aad binds every ciphertext to this format/version so a blob cannot be
// replayed into a different envelope revision.
var aad = []byte(fmt.Sprintf("%s/v%d", blobFormat, blobVersion))

// Protect wraps a PKCS#8 ML-DSA-65 key with the PIN using DefaultKDF.
func Protect(pkcs8 []byte, pin string) ([]byte, error) {
	return protect(pkcs8, pin, DefaultKDF)
}

func protect(pkcs8 []byte, pin string, kp KDF) ([]byte, error) {
	if len(pkcs8) == 0 {
		return nil, errors.New("webkeys: empty key")
	}
	if utf8.RuneCountInString(pin) < MinPINLength {
		return nil, ErrPINTooShort
	}
	wrapKey := make([]byte, wrapKeyLen)
	if _, err := io.ReadFull(rand.Reader, wrapKey); err != nil {
		return nil, err
	}
	defer wipe(wrapKey)

	keyNonce, keyCT, err := seal(wrapKey, pkcs8)
	if err != nil {
		return nil, err
	}
	b := blob{
		Format: blobFormat, Version: blobVersion, CreatedAt: time.Now().UTC(),
		KeyNonce: keyNonce, KeyCT: keyCT,
	}
	if err := b.wrapWithPIN(wrapKey, pin, kp); err != nil {
		return nil, err
	}
	return json.Marshal(&b)
}

// wrapWithPIN (re)seals wrapKey under a fresh salt and Argon2id(PIN).
func (b *blob) wrapWithPIN(wrapKey []byte, pin string, kp KDF) error {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	kp.Name, kp.Salt = "argon2id", salt
	pk := deriveKey(pin, kp)
	defer wipe(pk)
	nonce, ct, err := seal(pk, wrapKey)
	if err != nil {
		return err
	}
	b.KDF, b.WrapNonce, b.WrapCT = kp, nonce, ct
	return nil
}

// Unprotect reverses Protect and returns the PKCS#8 key. The caller must wipe
// the result as soon as the single operation that needs it completes.
func Unprotect(data []byte, pin string) ([]byte, error) {
	b, err := parse(data)
	if err != nil {
		return nil, err
	}
	wrapKey, err := b.openWrapKey(pin)
	if err != nil {
		return nil, err
	}
	defer wipe(wrapKey)
	pkcs8, err := openSeal(wrapKey, b.KeyNonce, b.KeyCT)
	if err != nil {
		return nil, ErrCorrupt
	}
	return pkcs8, nil
}

// ChangePIN re-wraps the blob under a new PIN without touching the key
// ciphertext (and without ever exposing the PKCS#8 key).
func ChangePIN(data []byte, oldPIN, newPIN string) ([]byte, error) {
	if utf8.RuneCountInString(newPIN) < MinPINLength {
		return nil, ErrPINTooShort
	}
	b, err := parse(data)
	if err != nil {
		return nil, err
	}
	wrapKey, err := b.openWrapKey(oldPIN)
	if err != nil {
		return nil, err
	}
	defer wipe(wrapKey)
	// Keep the parameters the blob already uses (they were bounds-checked).
	kp := b.KDF
	if err := b.wrapWithPIN(wrapKey, newPIN, kp); err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

func (b *blob) openWrapKey(pin string) ([]byte, error) {
	pk := deriveKey(pin, b.KDF)
	defer wipe(pk)
	wrapKey, err := openSeal(pk, b.WrapNonce, b.WrapCT)
	if err != nil {
		return nil, ErrWrongPIN
	}
	return wrapKey, nil
}

// parse decodes a blob and rejects anything this package did not produce,
// including KDF parameters outside the bounded range.
func parse(data []byte) (*blob, error) {
	var b blob
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if b.Format != blobFormat || b.Version != blobVersion {
		return nil, fmt.Errorf("%w: format %q version %d", ErrUnsupported, b.Format, b.Version)
	}
	k := b.KDF
	if k.Name != "argon2id" ||
		k.Time < 1 || k.Time > maxKDFTime ||
		k.Threads < 1 || k.Threads > maxKDFThreads ||
		k.MemKiB < minKDFMemKiB || k.MemKiB < 8*uint32(k.Threads) || k.MemKiB > maxKDFMemKiB ||
		len(k.Salt) < saltLen || len(k.Salt) > 64 {
		return nil, fmt.Errorf("%w: KDF parameters out of range", ErrUnsupported)
	}
	if len(b.WrapNonce) == 0 || len(b.WrapCT) == 0 || len(b.KeyNonce) == 0 || len(b.KeyCT) == 0 {
		return nil, ErrCorrupt
	}
	return &b, nil
}

func deriveKey(pin string, k KDF) []byte {
	return argon2.IDKey([]byte(pin), k.Salt, k.Time, k.MemKiB, k.Threads, wrapKeyLen)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

func seal(key, plaintext []byte) (nonce, ct []byte, err error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, plaintext, aad), nil
}

func openSeal(key, nonce, ct []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != g.NonceSize() {
		return nil, errors.New("bad nonce length")
	}
	return g.Open(nil, nonce, ct, aad)
}

// wipe best-effort zeroes a secret slice.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
