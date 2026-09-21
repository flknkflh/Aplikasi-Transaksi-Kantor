package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

const officeSecret = "office-secret-0123456789"

// upstream records what the office service would receive from the proxy.
type upstream struct {
	mu   sync.Mutex
	last *http.Request
	body []byte
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.last = r.Clone(r.Context())
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r.Body)
	u.body = buf.Bytes()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func officeEnv(t *testing.T) (*env, *upstream) {
	up := &upstream{}
	ts := httptest.NewServer(up)
	t.Cleanup(ts.Close)
	e := newEnvWith(t, func(c *api.Config) { c.OfficeUpstream = ts.URL; c.OfficeSecret = officeSecret })
	return e, up
}

func (e *env) doHdr(method, path, token string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

func TestOfficeProxyAuthenticatesAndVouchesForTheCaller(t *testing.T) {
	e, up := officeEnv(t)
	user := e.account("pemohon@test", store.RoleUser)

	// no session -> refused before anything reaches the office service
	if w := e.doHdr("GET", "/office/me", "", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if up.last != nil {
		t.Fatal("an unauthenticated call must not reach the upstream")
	}

	// a spoofed identity header and the bearer token must not pass through
	w := e.doHdr("POST", "/office/transactions?scope=x", user, []byte("payload"), map[string]string{
		"X-Office-Account": "acct_admin", "X-Office-Role": "superadmin", "X-Office-Secret": "guess",
	})
	if w.Code != 200 {
		t.Fatalf("proxy: %d %s", w.Code, w.Body.String())
	}
	got := up.last
	if got.URL.Path != "/office/transactions" || got.URL.RawQuery != "scope=x" || string(up.body) != "payload" {
		t.Fatalf("request not forwarded intact: %s?%s %q", got.URL.Path, got.URL.RawQuery, up.body)
	}
	if got.Header.Get("X-Office-Secret") != officeSecret {
		t.Fatal("proxy must present the shared secret")
	}
	if got.Header.Get("X-Office-Email") != "pemohon@test" || got.Header.Get("X-Office-Role") != "user" {
		t.Fatalf("identity headers: %v", got.Header)
	}
	if id := got.Header.Get("X-Office-Account"); id == "" || id == "acct_admin" {
		t.Fatalf("the caller's own header must be replaced by the authenticated account, got %q", id)
	}
	if got.Header.Get("Authorization") != "" {
		t.Fatal("the bearer token must not be forwarded")
	}
}

func TestOfficeProxyRefusesADisabledAccount(t *testing.T) {
	e, _ := officeEnv(t)
	user := e.account("nonaktif@test", store.RoleUser)
	w := e.do("GET", "/api/v1/admin/accounts", e.su, nil)
	mustCode(t, w, http.StatusOK)
	var id string
	for _, a := range jbodyAccounts(t, w) {
		if a["email"] == "nonaktif@test" {
			id, _ = a["account_id"].(string)
			if id == "" {
				id, _ = a["id"].(string)
			}
		}
	}
	if id == "" {
		t.Fatalf("account not listed: %s", w.Body.String())
	}
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/disable", e.su, nil), http.StatusOK)
	if w := e.doHdr("GET", "/office/me", user, nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("a disabled account must not use the office service: %d", w.Code)
	}
}

func jbodyAccounts(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	m := jbody(t, w)
	raw, _ := m["accounts"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if mm, ok := r.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}

func TestOfficeInternalSignatureLookup(t *testing.T) {
	e, _ := officeEnv(t)
	user := e.account("penanda@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	signed := signWith(t, d, pid)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusOK)

	// only with the shared secret
	for _, hdr := range []map[string]string{nil, {"X-Office-Secret": "wrong"}} {
		if w := e.doHdr("GET", "/internal/office/signatures/"+pid, "", nil, hdr); w.Code != http.StatusUnauthorized {
			t.Fatalf("without the secret: %d", w.Code)
		}
	}
	ok := map[string]string{"X-Office-Secret": officeSecret}
	w := e.doHdr("GET", "/internal/office/signatures/"+pid, "", nil, ok)
	mustCode(t, w, http.StatusOK)
	rec := jbody(t, w)
	if rec["verification_status"] != "accepted" || rec["public_id"] != pid {
		t.Fatalf("record: %v", rec)
	}
	if rec["signed_sha512"] != hashutil.CalculateSHA512(signed) {
		t.Fatalf("signed hash mismatch: %v", rec["signed_sha512"])
	}
	if id, _ := rec["account_id"].(string); id == "" {
		t.Fatalf("the record must name the signing account: %v", rec)
	}
	if !strings.HasPrefix(rec["verification_url"].(string), "https://verify.test/") {
		t.Fatalf("verification url: %v", rec["verification_url"])
	}
	d2 := e.doHdr("GET", "/internal/office/signatures/"+pid+"/document", "", nil, ok)
	if d2.Code != 200 || !bytes.Equal(d2.Body.Bytes(), signed) {
		t.Fatalf("signed document: %d", d2.Code)
	}
	if w := e.doHdr("GET", "/internal/office/signatures/sig_nope", "", nil, ok); w.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", w.Code)
	}
}

func TestOfficeIsOffUnlessConfigured(t *testing.T) {
	e := newEnv(t)
	if w := e.doHdr("GET", "/office/me", "", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured /office/ must be 404, got %d", w.Code)
	}
	if w := e.doHdr("GET", "/internal/office/signatures/x", "", nil, map[string]string{"X-Office-Secret": officeSecret}); w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured internal route must be 404, got %d", w.Code)
	}
	// a too-short secret also keeps it off
	e2 := newEnvWith(t, func(c *api.Config) { c.OfficeUpstream = "http://127.0.0.1:1"; c.OfficeSecret = "short" })
	if w := e2.doHdr("GET", "/office/me", "", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("a short secret must disable the office routes, got %d", w.Code)
	}
}
