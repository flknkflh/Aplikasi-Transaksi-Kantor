package webkeys

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/keys"
)

// fastKDF keeps tests quick; production uses DefaultKDF (see TestDefaultKDF).
var fastKDF = KDF{Name: "argon2id", Time: 1, MemKiB: 64, Threads: 1}

func testKey(t *testing.T) []byte {
	t.Helper()
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := keys.MarshalPKCS8(sk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return der
}

func TestRoundTripKeepsAWorkingMLDSAKey(t *testing.T) {
	pkcs8 := testKey(t)
	b, err := protect(pkcs8, "123456", fastKDF)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if bytes.Contains(b, pkcs8) {
		t.Fatal("blob must not contain the plaintext key")
	}
	got, err := Unprotect(b, "123456")
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if !bytes.Equal(got, pkcs8) {
		t.Fatal("round trip changed the key")
	}
	if _, err := keys.ParsePKCS8(got); err != nil {
		t.Fatalf("unwrapped key is not a valid ML-DSA-65 key: %v", err)
	}
}

func TestWrongPINIsRejected(t *testing.T) {
	b, _ := protect(testKey(t), "123456", fastKDF)
	if _, err := Unprotect(b, "654321"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("want ErrWrongPIN, got %v", err)
	}
	if _, err := Unprotect(b, ""); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("empty PIN must be rejected as wrong, got %v", err)
	}
}

func TestPINIsMandatoryAndMinimumLength(t *testing.T) {
	for _, pin := range []string{"", "1", "12345"} {
		if _, err := protect(testKey(t), pin, fastKDF); !errors.Is(err, ErrPINTooShort) {
			t.Fatalf("PIN %q: want ErrPINTooShort, got %v", pin, err)
		}
	}
	// Length is counted in characters, not bytes.
	if _, err := protect(testKey(t), "ééééé", fastKDF); !errors.Is(err, ErrPINTooShort) {
		t.Fatalf("5 multibyte characters must still be too short, got %v", err)
	}
	if _, err := protect(testKey(t), "éééééé", fastKDF); err != nil {
		t.Fatalf("6 characters must be accepted: %v", err)
	}
}

func TestEveryProtectIsFresh(t *testing.T) {
	pkcs8 := testKey(t)
	a, _ := protect(pkcs8, "123456", fastKDF)
	b, _ := protect(pkcs8, "123456", fastKDF)
	if bytes.Equal(a, b) {
		t.Fatal("two wraps of the same key must differ (fresh salt, nonces, wrapKey)")
	}
	for _, blob := range [][]byte{a, b} {
		if _, err := Unprotect(blob, "123456"); err != nil {
			t.Fatalf("unprotect: %v", err)
		}
	}
}

func mutate(t *testing.T, data []byte, f func(*blob)) []byte {
	t.Helper()
	var b blob
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	f(&b)
	out, err := json.Marshal(&b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTamperingIsDetected(t *testing.T) {
	good, _ := protect(testKey(t), "123456", fastKDF)

	if _, err := Unprotect(mutate(t, good, func(b *blob) { b.KeyCT[0] ^= 1 }), "123456"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("flipped key ciphertext: want ErrCorrupt, got %v", err)
	}
	if _, err := Unprotect(mutate(t, good, func(b *blob) { b.WrapCT[0] ^= 1 }), "123456"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("flipped wrapped-key ciphertext: want ErrWrongPIN, got %v", err)
	}
	if _, err := Unprotect(mutate(t, good, func(b *blob) { b.KDF.Salt[0] ^= 1 }), "123456"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("changed salt: want ErrWrongPIN, got %v", err)
	}
}

func TestUnknownFormatAndGarbageAreUnsupported(t *testing.T) {
	good, _ := protect(testKey(t), "123456", fastKDF)
	cases := map[string][]byte{
		"version":  mutate(t, good, func(b *blob) { b.Version = 2 }),
		"format":   mutate(t, good, func(b *blob) { b.Format = "pqc-other" }),
		"garbage":  []byte("not json"),
		"empty":    {},
		"kdf name": mutate(t, good, func(b *blob) { b.KDF.Name = "scrypt" }),
	}
	for name, data := range cases {
		if _, err := Unprotect(data, "123456"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: want ErrUnsupported, got %v", name, err)
		}
	}
}

// A blob is attacker-controlled input (it sits in browser storage). Its KDF
// parameters must never be trusted to size an allocation.
func TestMaliciousKDFParametersAreRefusedBeforeAnyWork(t *testing.T) {
	good, _ := protect(testKey(t), "123456", fastKDF)
	bad := map[string]func(*blob){
		"4 GiB memory":   func(b *blob) { b.KDF.MemKiB = 4 * 1024 * 1024 },
		"huge time cost": func(b *blob) { b.KDF.Time = 1 << 30 },
		"zero time cost": func(b *blob) { b.KDF.Time = 0 },
		"too many lanes": func(b *blob) { b.KDF.Threads = 255 },
		"zero lanes":     func(b *blob) { b.KDF.Threads = 0 },
		"tiny memory":    func(b *blob) { b.KDF.MemKiB = 1 },
		"short salt":     func(b *blob) { b.KDF.Salt = []byte{1, 2, 3} },
		"huge salt":      func(b *blob) { b.KDF.Salt = make([]byte, 1<<16) },
	}
	for name, f := range bad {
		start := time.Now()
		_, err := Unprotect(mutate(t, good, f), "123456")
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: want ErrUnsupported, got %v", name, err)
		}
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("%s: took %v — parameters must be rejected before doing KDF work", name, d)
		}
	}
}

func TestChangePIN(t *testing.T) {
	pkcs8 := testKey(t)
	old, _ := protect(pkcs8, "123456", fastKDF)
	changed, err := ChangePIN(old, "123456", "abcdef")
	if err != nil {
		t.Fatalf("change pin: %v", err)
	}
	if _, err := Unprotect(changed, "123456"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("old PIN must stop working, got %v", err)
	}
	got, err := Unprotect(changed, "abcdef")
	if err != nil || !bytes.Equal(got, pkcs8) {
		t.Fatalf("new PIN must open the same key: err=%v", err)
	}

	// The key ciphertext itself is untouched: only the wrapping changed.
	var a, b blob
	_ = json.Unmarshal(old, &a)
	_ = json.Unmarshal(changed, &b)
	if !bytes.Equal(a.KeyCT, b.KeyCT) || !bytes.Equal(a.KeyNonce, b.KeyNonce) {
		t.Fatal("ChangePIN must not re-encrypt the key")
	}
	if bytes.Equal(a.KDF.Salt, b.KDF.Salt) {
		t.Fatal("ChangePIN must use a fresh salt")
	}

	if _, err := ChangePIN(old, "wrong!", "abcdef"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("wrong old PIN: want ErrWrongPIN, got %v", err)
	}
	if _, err := ChangePIN(old, "123456", "short"); !errors.Is(err, ErrPINTooShort) {
		t.Fatalf("short new PIN: want ErrPINTooShort, got %v", err)
	}
}

// TestDefaultKDF exercises the real parameters once (64 MiB, t=3, p=4).
func TestDefaultKDF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the full-cost KDF in -short mode")
	}
	pkcs8 := testKey(t)
	start := time.Now()
	b, err := Protect(pkcs8, "correct horse")
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	got, err := Unprotect(b, "correct horse")
	if err != nil || !bytes.Equal(got, pkcs8) {
		t.Fatalf("round trip with default KDF failed: %v", err)
	}
	t.Logf("protect+unprotect with the default Argon2id parameters: %v", time.Since(start))
}
