package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// The super admin's separate login (docs/adr/0005-superadmin-login.md).

// saEnv is an env whose super admin is "boss": its first-login ceremony is still open in
// newEnvWith, so the test runs it itself and keeps the TOTP secret.
func saEnv(t *testing.T) (*env, string, string) { // env, super-admin token, TOTP secret
	t.Helper()
	e := newEnvWith(t, func(c *api.Config) { c.SuperAdminUsername = "boss"; c.SuperAdminPassword = "initial-password-1" })
	tok, secret := e.superAdminSetup("boss", "initial-password-1", "a-much-longer-superadmin-password")
	return e, tok, secret
}

func testRoot(t *testing.T) []byte {
	t.Helper()
	r, err := labpki.NewRootCA("Test Root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return labpki.CertPEM(r.Cert)
}

func TestSuperAdminIsCreatedAutomaticallyAndMustSetUpOnFirstLogin(t *testing.T) {
	st := backendStore(t)
	cfg := api.Config{RootCAPEM: testRoot(t), JWTSecret: []byte("test-secret-0123456789"), RateLimits: &api.RateLimits{},
		SuperAdminUsername: "boss", UploadDir: t.TempDir()} // no password configured
	if _, err := api.New(st, cfg); err != nil {
		t.Fatal(err)
	}
	var acct store.Account
	for _, a := range st.ListAccounts() {
		if a.Role == store.RoleSuperAdmin {
			acct = a
		}
	}
	if acct.ID == "" || acct.Email != "boss" || acct.Status != store.AccountActive {
		t.Fatalf("the super admin must exist right after startup: %+v", acct)
	}
	if acct.PasswordHash == "" {
		t.Fatal("a random initial password must have been generated (there is no built-in one)")
	}
	sec, err := st.SuperSecurity(acct.ID)
	if err != nil || !sec.MustChange || sec.TOTPEnabled {
		t.Fatalf("a fresh super admin must be forced to change the password and enrol TOTP: %+v %v", sec, err)
	}
	// starting again does not create a second one (the database also forbids it)
	if _, err := api.New(st, cfg); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range st.ListAccounts() {
		if a.Role == store.RoleSuperAdmin {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("exactly one super admin, got %d", n)
	}
}

func TestSuperAdminCannotUseTheOrdinaryLoginAndNobodyElseCanUseTheirs(t *testing.T) {
	e, _, _ := saEnv(t)
	// right password, wrong door: refused with a pointer to the right page, and no token
	w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "boss", "password": "a-much-longer-superadmin-password"})
	mustCode(t, w, http.StatusForbidden)
	b := jbody(t, w)
	if b["superadmin_login"] != true || b["access_token"] != nil {
		t.Fatalf("ordinary login must refuse the super admin without issuing a token: %v", b)
	}
	// wrong password on the ordinary login: the same generic failure as anyone
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "boss", "password": "wrong"}), http.StatusUnauthorized)

	// an ordinary user/admin cannot use the super-admin login
	e.account("someone@test", store.RoleUser)
	mustCode(t, e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "someone@test", "password": "password123"}), http.StatusUnauthorized)
	mustCode(t, e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "_admin@test", "password": "password123"}), http.StatusUnauthorized)
	// ...and cannot tell a missing name from a wrong password
	a := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "nobody", "password": "x"})
	c := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "x"})
	if a.Code != c.Code || jbody(t, a)["error"] != jbody(t, c)["error"] {
		t.Fatalf("unknown user and wrong password must look identical: %d %v / %d %v", a.Code, a.Body.String(), c.Code, c.Body.String())
	}
}

func TestSuperAdminTokenAndAdminTokenAreNotInterchangeable(t *testing.T) {
	e, su, _ := saEnv(t)
	// the super-admin session works on its own routes only
	mustCode(t, e.do("GET", "/api/v1/superadmin/me", su, nil), http.StatusOK)
	mustCode(t, e.do("GET", "/api/v1/superadmin/admins", su, nil), http.StatusOK)
	for _, p := range []string{"/api/v1/admin/accounts", "/api/v1/admin/audit-events", "/api/v1/admin/enrollments", "/api/v1/devices", "/api/v1/me/signatures"} {
		if w := e.do("GET", p, su, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("a super-admin token must be useless on %s (got %d)", p, w.Code)
		}
	}
	// an admin/user token is useless on the super-admin routes
	for _, tok := range []string{e.badmin, e.account("u@test", store.RoleUser)} {
		for _, p := range []string{"/api/v1/superadmin/me", "/api/v1/superadmin/admins"} {
			if w := e.do("GET", p, tok, nil); w.Code != http.StatusUnauthorized {
				t.Errorf("an ordinary token must be refused on %s (got %d)", p, w.Code)
			}
		}
	}
	// a challenge token (password only) is not a session
	w := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "a-much-longer-superadmin-password"})
	mustCode(t, w, http.StatusOK)
	ch := jbody(t, w)["challenge"].(string)
	if w := e.do("GET", "/api/v1/superadmin/admins", ch, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a password-only challenge must not open the console: %d", w.Code)
	}
	if w := e.do("GET", "/api/v1/superadmin/me", "garbage.token.value", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("garbage: %d", w.Code)
	}
}

func TestSuperAdminNeedsTheSecondFactorAndACodeWorksOnlyOnce(t *testing.T) {
	e, _, secret := saEnv(t)
	pw := "a-much-longer-superadmin-password"
	login := func() string {
		w := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": pw})
		mustCode(t, w, http.StatusOK)
		b := jbody(t, w)
		if b["step"] != "totp" || b["access_token"] != nil {
			t.Fatalf("after setup the password alone must lead to the code step, never a session: %v", b)
		}
		return b["challenge"].(string)
	}
	verify := func(ch, code string) *httptest.ResponseRecorder {
		return e.do("POST", "/api/v1/superadmin/verify", "", map[string]string{"challenge": ch, "code": code})
	}
	step := e.saStep // the step the enrolment code was for (immune to a 30 s boundary falling mid-test)
	codeFor := func(s int64) string { c, _ := auth.TOTPCodeAt(secret, s); return c }

	// the code used during setup cannot be replayed
	if w := verify(login(), codeFor(step)); w.Code != http.StatusUnauthorized {
		t.Fatalf("the enrolment code (already used) must be refused: %d", w.Code)
	}
	// a wrong code is refused
	if w := verify(login(), "000000"); w.Code == http.StatusOK {
		t.Fatal("a wrong code must not log in")
	}
	// the next step's code (within the accepted drift) works...
	w := verify(login(), codeFor(step+1))
	mustCode(t, w, http.StatusOK)
	tok := jbody(t, w)["access_token"].(string)
	mustCode(t, e.do("GET", "/api/v1/superadmin/me", tok, nil), http.StatusOK)
	// ...but only once
	if w := verify(login(), codeFor(step+1)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a TOTP code must work only once: %d", w.Code)
	}
	// a code-step challenge cannot be used at the setup endpoints, nor vice versa
	ch := login()
	mustCode(t, e.do("POST", "/api/v1/superadmin/setup/begin", "", map[string]string{"challenge": ch, "new_password": "another-very-long-password"}), http.StatusUnauthorized)
	if w := e.do("POST", "/api/v1/superadmin/verify", "", map[string]string{"challenge": "x.y.z", "code": "123456"}); w.Code != http.StatusUnauthorized {
		t.Errorf("garbage challenge: %d", w.Code)
	}
}

func TestSuperAdminSetupRules(t *testing.T) {
	e := newEnvWith(t, func(c *api.Config) { c.SuperAdminUsername = "boss"; c.SuperAdminPassword = "initial-password-1" })
	w := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "initial-password-1"})
	mustCode(t, w, http.StatusOK)
	ch := jbody(t, w)["challenge"].(string)
	begin := func(pw string) int {
		return e.do("POST", "/api/v1/superadmin/setup/begin", "", map[string]string{"challenge": ch, "new_password": pw}).Code
	}
	if begin("short") != http.StatusBadRequest {
		t.Error("a short password must be refused")
	}
	if begin("initial-password-1") != http.StatusBadRequest {
		t.Error("keeping the initial password must be refused")
	}
	if begin("boss") != http.StatusBadRequest {
		t.Error("the username as a password must be refused")
	}
	// TOTP cannot be confirmed before the new password was set (must_change is still on)
	if c := e.do("POST", "/api/v1/superadmin/setup/confirm", "", map[string]string{"challenge": ch, "code": "123456"}).Code; c != http.StatusConflict {
		t.Errorf("confirming before setup begins must be refused: %d", c)
	}
	if begin("a-much-longer-superadmin-password") != http.StatusOK {
		t.Fatal("a good password must be accepted")
	}
	// the initial password is gone the moment the new one is set, even if the ceremony is abandoned
	if c := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "initial-password-1"}).Code; c != http.StatusUnauthorized {
		t.Errorf("the initial password must stop working: %d", c)
	}
	// abandoned before confirming: the next login returns to setup (no session without TOTP)
	w = e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "a-much-longer-superadmin-password"})
	mustCode(t, w, http.StatusOK)
	if b := jbody(t, w); b["step"] != "setup" || b["must_change"] != false {
		t.Fatalf("an unenrolled account must return to setup, without another password change: %v", b)
	}
	// a wrong confirmation code is refused
	ch = jbody(t, w)["challenge"].(string)
	mustCode(t, e.do("POST", "/api/v1/superadmin/setup/begin", "", map[string]string{"challenge": ch}), http.StatusOK)
	if c := e.do("POST", "/api/v1/superadmin/setup/confirm", "", map[string]string{"challenge": ch, "code": "000000"}).Code; c != http.StatusUnauthorized {
		t.Errorf("a wrong enrolment code must be refused: %d", c)
	}
}

func TestSuperAdminLockoutAfterRepeatedFailures(t *testing.T) {
	e, _, _ := saEnv(t)
	for i := 0; i < 5; i++ {
		if c := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "wrong-" + string(rune('a'+i))}).Code; c != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	w := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "a-much-longer-superadmin-password"})
	if w.Code != http.StatusTooManyRequests || jbody(t, w)["retry_after"] == nil {
		t.Fatalf("after 5 failures even the right password must be refused for a while: %d %s", w.Code, w.Body.String())
	}
	// the failures are in the audit trail
	if w := e.do("GET", "/api/v1/admin/audit-events", e.badmin, nil); !strings.Contains(w.Body.String(), "superadmin.lock") {
		t.Errorf("the lockout must be audited: %s", w.Body.String())
	}
}

func TestSuperAdminChangePasswordAndManagesAdminsOnly(t *testing.T) {
	e, su, _ := saEnv(t)
	cp := func(cur, nw string) int {
		return e.do("POST", "/api/v1/superadmin/change-password", su, map[string]string{"current": cur, "new": nw}).Code
	}
	if cp("wrong", "yet-another-long-password") != http.StatusForbidden {
		t.Error("the current password is required")
	}
	if cp("a-much-longer-superadmin-password", "short") != http.StatusBadRequest {
		t.Error("a short new password must be refused")
	}
	if cp("a-much-longer-superadmin-password", "a-much-longer-superadmin-password") != http.StatusBadRequest {
		t.Error("the same password must be refused")
	}
	if cp("a-much-longer-superadmin-password", "yet-another-long-password") != http.StatusOK {
		t.Fatal("a valid change must succeed")
	}
	if c := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "a-much-longer-superadmin-password"}).Code; c != http.StatusUnauthorized {
		t.Errorf("the old password must stop working: %d", c)
	}
	if c := e.do("POST", "/api/v1/superadmin/login", "", map[string]string{"username": "boss", "password": "yet-another-long-password"}).Code; c != http.StatusOK {
		t.Errorf("the new password must work: %d", c)
	}

	// what the super admin creates is an ordinary admin: logs in the ordinary way, uses the
	// admin console, but cannot reach the super-admin routes.
	w := e.do("POST", "/api/v1/superadmin/admins", su, map[string]string{"username": "new-admin@test", "password": "password123"})
	mustCode(t, w, http.StatusCreated)
	adminTok := e.login("new-admin@test")
	mustCode(t, e.do("GET", "/api/v1/admin/accounts", adminTok, nil), http.StatusOK)
	mustCode(t, e.do("GET", "/api/v1/superadmin/admins", adminTok, nil), http.StatusUnauthorized)
}

func TestSuperAdminPageIsServedUnderAStrictCSP(t *testing.T) {
	e := newEnv(t)
	w := e.do("GET", "/superadmin/", "", nil)
	mustCode(t, w, http.StatusOK)
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP: %q", csp)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Robots-Tag") == "" {
		t.Errorf("the page must not be cached or indexed: %v", w.Header())
	}
	if !strings.Contains(w.Body.String(), "Super Admin") || strings.Contains(w.Body.String(), "<script>") {
		t.Errorf("unexpected page body")
	}
	mustCode(t, e.do("GET", "/superadmin/superadmin.js", "", nil), http.StatusOK)
	mustCode(t, e.do("GET", "/superadmin/superadmin.css", "", nil), http.StatusOK)
	if w := e.do("GET", "/superadmin", "", nil); w.Code != http.StatusMovedPermanently {
		t.Errorf("/superadmin must redirect to /superadmin/: %d", w.Code)
	}
	if w := e.do("GET", "/superadmin/../api/v1/admin/accounts", "", nil); w.Code == http.StatusOK {
		t.Error("path tricks must not reach anything")
	}
}

func TestBootstrapAdminOnlyWhenThereIsNone(t *testing.T) {
	st := backendStore(t)
	cfg := api.Config{RootCAPEM: testRoot(t), JWTSecret: []byte("test-secret-0123456789"), RateLimits: &api.RateLimits{}, UploadDir: t.TempDir(),
		BootstrapAdminEmail: "seed@test", BootstrapAdminPassword: "seed-password-1"}
	if _, err := api.New(st, cfg); err != nil {
		t.Fatal(err)
	}
	if a, err := st.AccountByEmail("seed@test"); err != nil || a.Role != store.RoleAdmin {
		t.Fatalf("the bootstrap admin must be created when there is no admin: %+v %v", a, err)
	}
	cfg.BootstrapAdminEmail = "second@test"
	if _, err := api.New(st, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AccountByEmail("second@test"); err == nil {
		t.Fatal("no second bootstrap admin once an admin exists")
	}
}
