package auth

import (
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("x", "not-a-hash") {
		t.Fatal("garbage hash accepted")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("hash is not salted (identical output for same input)")
	}
}

func TestJWTRoundTrip(t *testing.T) {
	s := NewSigner([]byte("0123456789abcdef"), time.Minute)
	tok := s.Issue("acct_1", "admin")
	c, err := s.Parse(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Sub != "acct_1" || c.Role != "admin" {
		t.Fatalf("claims = %+v", c)
	}
}

func TestJWTRejectsTamperAndWrongKey(t *testing.T) {
	s := NewSigner([]byte("0123456789abcdef"), time.Minute)
	tok := s.Issue("acct_1", "user")

	bad := tok[:len(tok)-2] + "xx"
	if _, err := s.Parse(bad); err == nil {
		t.Fatal("tampered signature accepted")
	}
	other := NewSigner([]byte("different-key-000"), time.Minute)
	if _, err := other.Parse(tok); err == nil {
		t.Fatal("token verified under the wrong key")
	}
}
