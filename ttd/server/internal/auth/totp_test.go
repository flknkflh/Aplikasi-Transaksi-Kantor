package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B (SHA-1, secret "12345678901234567890"); the RFC lists 8-digit
// codes, ours are the last 6 digits of the same HOTP value.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for _, c := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := TOTPCodeAt(secret, TOTPStep(time.Unix(c.unix, 0)))
		if err != nil || got != c.want {
			t.Errorf("t=%d: got %q err=%v, want %s", c.unix, got, err, c.want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	step := TOTPStep(now)
	code := func(s int64) string { c, _ := TOTPCodeAt(secret, s); return c }

	if got, ok := VerifyTOTP(secret, code(step), now, 0); !ok || got != step {
		t.Fatalf("the current code must verify: %v %v", got, ok)
	}
	if _, ok := VerifyTOTP(secret, code(step-1), now, 0); !ok {
		t.Error("one step of clock drift is tolerated (past)")
	}
	if _, ok := VerifyTOTP(secret, code(step+1), now, 0); !ok {
		t.Error("one step of clock drift is tolerated (future)")
	}
	if _, ok := VerifyTOTP(secret, code(step-2), now, 0); ok {
		t.Error("two steps old must be refused")
	}
	if _, ok := VerifyTOTP(secret, code(step), now, step); ok {
		t.Error("a code for an already-used step must be refused (replay)")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Error("a short code must be refused")
	}
	if _, ok := VerifyTOTP(secret, code(step)+"0", now, 0); ok {
		t.Error("a long code must be refused")
	}
	if got, ok := VerifyTOTP(secret, " "+code(step)[:3]+" "+code(step)[3:], now, 0); !ok || got != step {
		t.Error("spaces in a typed code are tolerated")
	}
	other := NewTOTPSecret()
	if c, _ := TOTPCodeAt(other, step); c != code(step) {
		if _, ok := VerifyTOTP(secret, c, now, 0); ok {
			t.Error("another secret's code must be refused")
		}
	}
}

func TestTOTPURIIsWhatAuthenticatorsExpect(t *testing.T) {
	u := TOTPURI("Arsip Pusat", "superadmin", "JBSWY3DPEHPK3PXP")
	for _, want := range []string{"otpauth://totp/Arsip%20Pusat:superadmin?", "secret=JBSWY3DPEHPK3PXP", "issuer=Arsip+Pusat", "digits=6", "period=30", "algorithm=SHA1"} {
		if !strings.Contains(u, want) {
			t.Errorf("uri %q lacks %q", u, want)
		}
	}
}
