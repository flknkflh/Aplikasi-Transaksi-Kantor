package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

func webAppHandler(t *testing.T, dir string) http.Handler {
	t.Helper()
	root, _ := labpki.NewRootCA("Test Root", 10*365*24*time.Hour)
	srv, err := api.New(store.NewMemory(), api.Config{
		RootCAPEM: labpki.CertPEM(root.Cert), JWTSecret: []byte("test-secret-0123456789"),
		PublicBaseURL: "https://verify.test", RateLimits: &api.RateLimits{}, WebDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Routes()
}

func get(h http.Handler, path string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestWebAppIsServedUnderAStrictCSP(t *testing.T) {
	dir := t.TempDir()
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("index.html", "<!doctype html><title>x</title>"+strings.Repeat("<p>hello</p>", 200))
	must("pqcsign.wasm", "\x00asm\x01\x00\x00\x00"+strings.Repeat("\x00", 4096))
	must("app.js", "export const x = 1;")
	must(".secret", "hidden")
	h := webAppHandler(t, dir)

	w := get(h, "/app/")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("index: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'self' 'wasm-unsafe-eval'", "style-src 'self'", "connect-src 'self'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("CSP must not allow inline or eval: %s", csp)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("missing hardening headers: %v", w.Header())
	}

	if ct := get(h, "/app/pqcsign.wasm").Header().Get("Content-Type"); ct != "application/wasm" {
		t.Errorf("wasm content type = %q", ct)
	}
	if ct := get(h, "/app/app.js").Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("js content type = %q", ct)
	}

	// gzip when the client accepts it, identity otherwise
	gz := get(h, "/app/", "Accept-Encoding", "gzip")
	if gz.Header().Get("Content-Encoding") != "gzip" || gz.Body.Len() >= w.Body.Len() {
		t.Errorf("expected a smaller gzip body: enc=%q %d vs %d", gz.Header().Get("Content-Encoding"), gz.Body.Len(), w.Body.Len())
	}
	if w.Header().Get("Content-Encoding") != "" {
		t.Errorf("identity response must not be encoded")
	}

	// conditional GET
	if get(h, "/app/", "If-None-Match", w.Header().Get("ETag")).Code != http.StatusNotModified {
		t.Errorf("matching ETag should give 304")
	}

	// no traversal, no dotfiles, unknown -> 404, /app -> /app/
	for _, p := range []string{"/app/../go.mod", "/app/%2e%2e/api.go", "/app/.secret", "/app/nope.js", "/app/../../etc/passwd"} {
		if c := get(h, p).Code; c == 200 {
			t.Errorf("%s must not be served (got %d)", p, c)
		}
	}
	if c := get(h, "/app"); c.Code != http.StatusMovedPermanently || c.Header().Get("Location") != "/app/" {
		t.Errorf("/app should redirect to /app/: %d %q", c.Code, c.Header().Get("Location"))
	}
}

func TestWebAppNotBuiltAnswers503(t *testing.T) {
	if c := get(webAppHandler(t, t.TempDir()), "/app/").Code; c != http.StatusServiceUnavailable {
		t.Fatalf("an empty web dir must answer 503, got %d", c)
	}
}

// The architecture's central promise: the server never signs. Serving the
// browser client must not have added a signing route.
func TestServerStillHasNoSigningEndpoint(t *testing.T) {
	h := webAppHandler(t, t.TempDir())
	for _, p := range []string{"/api/v1/sign", "/api/v1/signatures/sign", "/api/v1/sign/pdf"} {
		for _, m := range []string{"POST", "PUT"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(m, p, strings.NewReader("x")))
			if w.Code != 404 && w.Code != 405 {
				t.Errorf("%s %s = %d, want 404/405", m, p, w.Code)
			}
		}
	}
}

// Guards the client's CSP compatibility at the source: the page must never gain
// an inline script, inline style attribute or inline event handler, or the
// strict CSP would silently break it (or, worse, get loosened to make it work).
func TestBrowserClientSourceIsCSPClean(t *testing.T) {
	for _, app := range []string{"arsip", "src"} { // the archive client and the earlier PDF-signing client
		checkClientCSP(t, filepath.Join("..", "..", "..", "web", app))
	}
	checkClientCSP(t, "superadmin") // the separate super-admin page
}

func checkClientCSP(t *testing.T, src string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Skipf("client sources not present: %v", err)
	}
	inlineScript := regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>\s*[^<\s]`)
	styleAttr := regexp.MustCompile(`(?i)\sstyle\s*=`)
	handler := regexp.MustCompile(`(?i)\son[a-z]+\s*=\s*["']`)
	styleTag := regexp.MustCompile(`(?i)<style[\s>]`)
	evalUse := regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["']`)
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".html") || strings.HasSuffix(e.Name(), ".js")) {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(src, e.Name()))
		s := string(b)
		name := filepath.Base(src) + "/" + e.Name()
		if strings.HasSuffix(e.Name(), ".html") && inlineScript.MatchString(s) {
			t.Errorf("%s: inline <script> body", name)
		}
		if styleAttr.MatchString(s) || styleTag.MatchString(s) {
			t.Errorf("%s: inline style", name)
		}
		if handler.MatchString(s) {
			t.Errorf("%s: inline event handler", name)
		}
		if evalUse.MatchString(s) {
			t.Errorf("%s: eval-like construct", name)
		}
	}
}
