package api_test

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// HSTS (docs/adr/0009): sent when the connection is actually secure, withheld
// over plain HTTP — sending it there is a no-op browsers ignore per spec, so
// omitting it is the spec-correct behavior, not an oversight.

func TestHSTSSentOverTLSWithheldOverPlainHTTP(t *testing.T) {
	e := newEnv(t)

	plain := httptest.NewRequest("GET", "/api/v1/public/server", nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, plain)
	if h := w.Header().Get("Strict-Transport-Security"); h != "" {
		t.Fatalf("HSTS must not be sent over plain HTTP, got %q", h)
	}

	secure := httptest.NewRequest("GET", "/api/v1/public/server", nil)
	secure.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	w = httptest.NewRecorder()
	e.h.ServeHTTP(w, secure)
	h := w.Header().Get("Strict-Transport-Security")
	if h == "" {
		t.Fatal("HSTS must be sent when the connection is native TLS")
	}
	if !contains(h, "max-age=") || !contains(h, "includeSubDomains") {
		t.Fatalf("HSTS header missing expected directives: %q", h)
	}

	behindProxy := httptest.NewRequest("GET", "/api/v1/public/server", nil)
	behindProxy.Header.Set("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	e.h.ServeHTTP(w, behindProxy)
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS must also be sent when X-Forwarded-Proto: https (behind a TLS-terminating proxy)")
	}
}

func TestHSTSAlsoAppliesToTheVerifyOnlyService(t *testing.T) {
	root, _ := labpki.NewRootCA("HSTS Root", 0)
	srv, err := api.New(store.NewMemory(), api.Config{
		RootCAPEM:  labpki.CertPEM(root.Cert),
		JWTSecret:  []byte("test-secret-0123456789"),
		RateLimits: &api.RateLimits{},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.VerifyRoutes()

	req := httptest.NewRequest("GET", "/api/v1/public/ca/root.crt", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("VerifyRoutes must also send HSTS over TLS")
	}
}
