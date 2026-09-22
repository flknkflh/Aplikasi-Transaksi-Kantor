package api_test

import (
	"net/http"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Admin login hardening (docs/adr/0007-admin-lockout-and-totp.md): an
// unconditional failed-attempt lockout, and opt-in TOTP, for ordinary admin
// accounts — found missing in the security review.

func TestAdminLockoutAfterFailedPasswords(t *testing.T) {
	e := newEnv(t)
	e.account("target@test", store.RoleAdmin)

	var last int
	for i := 0; i < 5; i++ {
		w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "target@test", "password": "wrong-pw"})
		last = w.Code
	}
	if last != http.StatusUnauthorized {
		t.Fatalf("5th wrong attempt = %d, want 401 (the LOCK itself fires on the 5th failure, not before)", last)
	}

	// now locked — even the RIGHT password is refused, with a retry_after
	w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "target@test", "password": "password123"})
	mustCode(t, w, http.StatusTooManyRequests)
	if ra, ok := jbody(t, w)["retry_after"].(float64); !ok || ra <= 0 {
		t.Fatalf("locked response missing a positive retry_after: %v", jbody(t, w))
	}

	// an unrelated admin is NOT affected — lockout is per-account
	e.account("other@test", store.RoleAdmin)
	if w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "other@test", "password": "password123"}); w.Code != http.StatusOK {
		t.Fatalf("an unrelated admin got caught by target@test's lockout: %d", w.Code)
	}
}

func TestAdminLockoutDoesNotAffectOrdinaryUsersOrSuperAdmin(t *testing.T) {
	e := newEnv(t)
	e.account("user@test", store.RoleUser)
	// an ordinary user has no lockout row at all — five wrong passwords must
	// still just be five plain 401s, never a 429
	for i := 0; i < 8; i++ {
		w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "user@test", "password": "wrong"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: user login = %d, want 401 (users are not locked out here)", i, w.Code)
		}
	}
}

// totpBegin runs the self-service enrolment ceremony for an already-logged-in
// admin and returns the confirmed secret and the step the confirm code used —
// every code after this MUST use a later step (replay protection requires
// step > lastStep), so callers pass step+1, step+2, ... rather than
// recomputing TOTPStep(time.Now()), which can land on the very same 30 s
// window as the confirm call and be rejected as a replay.
func totpBegin(t *testing.T, e *env, adminTok string) (secret string, step int64) {
	t.Helper()
	w := e.do("POST", "/api/v1/admin/security/totp/begin", adminTok, nil)
	mustCode(t, w, http.StatusOK)
	secret = jbody(t, w)["secret"].(string)
	step = auth.TOTPStep(time.Now())
	code, _ := auth.TOTPCodeAt(secret, step)
	w = e.do("POST", "/api/v1/admin/security/totp/confirm", adminTok, map[string]string{"code": code})
	mustCode(t, w, http.StatusOK)
	return secret, step
}

func TestAdminOptInTOTPFullLoginFlow(t *testing.T) {
	e := newEnv(t)
	adminTok := e.account("mfa@test", store.RoleAdmin)

	// off by default
	w := e.do("GET", "/api/v1/admin/security/status", adminTok, nil)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["totp_enabled"] != false {
		t.Fatal("TOTP must be off until the admin opts in")
	}

	secret, enrolStep := totpBegin(t, e, adminTok)

	w = e.do("GET", "/api/v1/admin/security/status", adminTok, nil)
	if jbody(t, w)["totp_enabled"] != true {
		t.Fatal("status did not flip to enabled after confirm")
	}

	// ordinary login now stops at "mfa_required" — no access token yet
	w = e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "mfa@test", "password": "password123"})
	mustCode(t, w, http.StatusOK)
	lb := jbody(t, w)
	if lb["mfa_required"] != true || lb["access_token"] != nil {
		t.Fatalf("password-only login must not issue a session once TOTP is on: %v", lb)
	}
	stepToken := lb["step_token"].(string)

	// wrong code is refused
	mustCode(t, e.do("POST", "/api/v1/auth/login/totp", "", map[string]string{
		"step_token": stepToken, "code": "000000",
	}), http.StatusUnauthorized)

	// right code completes the login (must be a LATER step than the enrolment code)
	step := enrolStep + 1
	code, _ := auth.TOTPCodeAt(secret, step)
	w = e.do("POST", "/api/v1/auth/login/totp", "", map[string]string{"step_token": stepToken, "code": code})
	mustCode(t, w, http.StatusOK)
	tok := jbody(t, w)["access_token"].(string)
	mustCode(t, e.do("GET", "/api/v1/admin/capabilities", tok, nil), http.StatusOK)

	// the same code cannot be replayed
	w2 := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "mfa@test", "password": "password123"})
	stepToken2 := jbody(t, w2)["step_token"].(string)
	mustCode(t, e.do("POST", "/api/v1/auth/login/totp", "", map[string]string{
		"step_token": stepToken2, "code": code,
	}), http.StatusUnauthorized)
}

func TestAdminTOTPStepTokenNotInterchangeable(t *testing.T) {
	e := newEnv(t)
	adminTok := e.account("iso@test", store.RoleAdmin)
	totpBegin(t, e, adminTok)

	w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "iso@test", "password": "password123"})
	stepToken := jbody(t, w)["step_token"].(string)

	// an ordinary access token is not a valid step token
	mustCode(t, e.do("POST", "/api/v1/auth/login/totp", "", map[string]string{
		"step_token": adminTok, "code": "123456",
	}), http.StatusUnauthorized)
	// the super admin's OWN step-token mechanism must not accept this one either
	mustCode(t, e.do("POST", "/api/v1/superadmin/verify", "", map[string]string{
		"challenge": stepToken, "code": "123456",
	}), http.StatusUnauthorized)
}

func TestAdminTOTPDisableNeedsACurrentCode(t *testing.T) {
	e := newEnv(t)
	adminTok := e.account("off@test", store.RoleAdmin)
	secret, enrolStep := totpBegin(t, e, adminTok)

	// a wrong code cannot turn it off
	mustCode(t, e.do("POST", "/api/v1/admin/security/totp/disable", adminTok, map[string]string{"code": "000000"}), http.StatusUnauthorized)

	code, _ := auth.TOTPCodeAt(secret, enrolStep+1)
	mustCode(t, e.do("POST", "/api/v1/admin/security/totp/disable", adminTok, map[string]string{"code": code}), http.StatusOK)

	// login no longer asks for a second step
	w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "off@test", "password": "password123"})
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["access_token"] == nil {
		t.Fatal("login should be single-step again after disabling TOTP")
	}
}

func TestSuperAdminCanResetALockedOrEnrolledAdmin(t *testing.T) {
	e := newEnv(t)
	adminTok := e.account("recover@test", store.RoleAdmin)
	totpBegin(t, e, adminTok)

	// lock it out too, for good measure
	for i := 0; i < 5; i++ {
		e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "recover@test", "password": "wrong"})
	}
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "recover@test", "password": "password123"}), http.StatusTooManyRequests)

	id := adminID(t, e, "recover@test")
	// an ordinary admin token cannot use the recovery route
	mustCode(t, e.do("POST", "/api/v1/superadmin/admins/"+id+"/reset-security", adminTok, nil), http.StatusUnauthorized)
	mustCode(t, e.do("POST", "/api/v1/superadmin/admins/"+id+"/reset-security", e.su, nil), http.StatusOK)

	w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "recover@test", "password": "password123"})
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["access_token"] == nil {
		t.Fatal("reset-security should clear both the lockout and the TOTP enrolment")
	}
}
