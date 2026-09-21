// Package auth does password hashing (Argon2id) and short-lived bearer tokens
// (HS256 JWT) for the receiver server (Rencana V1 §24). MFA/TOTP and
// refresh-token revocation are M6 slice 2.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// --- Argon2id password hashing ---

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns an encoded Argon2id hash ("$argon2id$v=19$m=...,t=...,p=...$salt$hash").
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64(salt), b64(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var mem, tCost uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &tCost, &par); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, tCost, mem, par, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- HS256 JWT (minimal, no external dep) ---

type Claims struct {
	Sub  string `json:"sub"`  // account id
	Role string `json:"role"` // "user" | "admin"
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat"`
}

var ErrInvalidToken = errors.New("auth: invalid or expired token")

type Signer struct {
	secret []byte
	ttl    time.Duration
}

func NewSigner(secret []byte, ttl time.Duration) *Signer {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Signer{secret: secret, ttl: ttl}
}

func (s *Signer) TTL() time.Duration { return s.ttl }

func (s *Signer) Issue(accountID, role string) string {
	now := time.Now()
	c := Claims{Sub: accountID, Role: role, Iat: now.Unix(), Exp: now.Add(s.ttl).Unix()}
	header := b64json(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload := b64json(c)
	signing := header + "." + payload
	return signing + "." + s.mac(signing)
}

func (s *Signer) Parse(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidToken
	}
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(s.mac(parts[0]+"."+parts[1]))) != 1 {
		return Claims{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if time.Now().Unix() >= c.Exp {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}

func (s *Signer) mac(msg string) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func b64json(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}
