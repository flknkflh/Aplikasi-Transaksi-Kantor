package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Closes the "rate limit missing on /auth/register and /office/*" gap found in
// the security review (docs/adr/0007).

func TestRegisterIsRateLimited(t *testing.T) {
	e := newEnv(t)
	root, _ := labpki.NewRootCA("RL Root", 0)
	srv, err := api.New(store.NewMemory(), api.Config{
		RootCAPEM:  labpki.CertPEM(root.Cert),
		JWTSecret:  []byte("test-secret-0123456789"),
		RateLimits: &api.RateLimits{RegisterPerIP: 6},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = srv.Routes()

	got429 := false
	for i := 0; i < 25; i++ {
		w := e.do("POST", "/api/v1/auth/register", "", map[string]string{
			"email": "flood@test", "password": "password123",
		})
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("register endpoint never rate-limited after 25 rapid attempts")
	}
}

func TestOfficeProxyIsRateLimitedPerAccount(t *testing.T) {
	up := &upstream{}
	ts := httptest.NewServer(up)
	t.Cleanup(ts.Close)

	e := newEnvWith(t, func(c *api.Config) {
		c.OfficeUpstream = ts.URL
		c.OfficeSecret = officeSecret
		c.RateLimits = &api.RateLimits{OfficePerAccount: 6}
	})
	user := e.account("pengirim@test", store.RoleUser)

	got429 := false
	for i := 0; i < 25; i++ {
		w := e.doHdr("GET", "/office/ping", user, nil, nil)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("/office/* never rate-limited after 25 rapid requests from the same account")
	}

	// a DIFFERENT account gets its own bucket — not starved by the first one
	other := e.account("lain@test", store.RoleUser)
	if w := e.doHdr("GET", "/office/ping", other, nil, nil); w.Code == http.StatusTooManyRequests {
		t.Fatal("rate limit must be keyed per account, not global")
	}
}
