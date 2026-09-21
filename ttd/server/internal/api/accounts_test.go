package api_test

import (
	"net/http"
	"testing"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// RB-1: a self-registered account is pending until an admin approves, and a
// disabled account both loses its session and has every certificate revoked.

func TestAccountApprovalGate(t *testing.T) {
	e := newEnv(t)
	admin := e.account("admin@test", store.RoleAdmin)

	w := e.do("POST", "/api/v1/auth/register", "", map[string]string{
		"email": "pegawai@test", "password": "password123",
		"full_name": "Budi Pegawai", "organization": "Dinas X",
	})
	mustCode(t, w, http.StatusCreated)
	body := jbody(t, w)
	if body["status"] != store.AccountPending {
		t.Fatalf("register status = %v, want pending", body["status"])
	}
	id := body["account_id"].(string)

	// login is refused while pending
	w = e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"})
	mustCode(t, w, http.StatusForbidden)
	if jbody(t, w)["account_status"] != store.AccountPending {
		t.Fatalf("login body = %s", w.Body.String())
	}

	// admin approves -> login works
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/approve", admin, nil), http.StatusOK)
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"}), http.StatusOK)

	// admin disables -> login refused again
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/disable", admin, nil), http.StatusOK)
	w = e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"})
	mustCode(t, w, http.StatusForbidden)
	if jbody(t, w)["account_status"] != store.AccountDisabled {
		t.Fatalf("login body = %s", w.Body.String())
	}

	// re-enable
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/enable", admin, nil), http.StatusOK)
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"}), http.StatusOK)
}

// Admin accounts are managed ONLY by the super admin, ONLY via /admin/admins
// (full CRUD). The regular /admin/accounts/* routes are for client (user)
// accounts and refuse any admin/superadmin target.
func TestAdminManagedBySuperAdmin(t *testing.T) {
	e := newEnv(t) // api.New bootstrapped the super admin; e.su is its token
	admin := e.account("admin@test", store.RoleAdmin)

	login := func(email, pw string) int {
		return e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": email, "password": pw}).Code
	}

	// role in the register body is ignored — you get a pending end user
	w := e.do("POST", "/api/v1/auth/register", "", map[string]string{
		"email": "wannabe@test", "password": "password123", "role": store.RoleAdmin,
	})
	mustCode(t, w, http.StatusCreated)
	if b := jbody(t, w); b["role"] != store.RoleUser || b["status"] != store.AccountPending {
		t.Fatalf("register role/status = %v/%v, want user/pending", b["role"], b["status"])
	}

	// CREATE — a plain admin cannot; the super admin can, and it is active
	mustCode(t, e.do("POST", "/api/v1/admin/admins", admin, map[string]string{
		"username": "x@test", "password": "password123"}), http.StatusForbidden)
	w = e.do("POST", "/api/v1/admin/admins", e.su, map[string]string{
		"username": "admin2@test", "password": "password123"})
	mustCode(t, w, http.StatusCreated)
	nb := jbody(t, w)
	if nb["role"] != store.RoleAdmin || nb["status"] != store.AccountActive {
		t.Fatalf("new admin = %v/%v, want admin/active", nb["role"], nb["status"])
	}
	id2 := nb["account_id"].(string)
	if login("admin2@test", "password123") != http.StatusOK {
		t.Fatal("new admin cannot log in")
	}

	// READ — roster is admins only (no client accounts)
	e.account("someuser@test", store.RoleUser)
	admins := jbody(t, e.do("GET", "/api/v1/admin/admins", e.su, nil))["admins"].([]any)
	for _, a := range admins {
		if role := a.(map[string]any)["role"]; role != store.RoleAdmin && role != store.RoleSuperAdmin {
			t.Fatalf("admin roster leaked a %v", role)
		}
	}
	if len(admins) < 3 { // _su@test + admin@test + admin2@test
		t.Fatalf("admin roster too short: %v", admins)
	}

	// UPDATE — reset password + toggle status, super admin only, via /admin/admins/{id}
	mustCode(t, e.do("PATCH", "/api/v1/admin/admins/"+id2, admin, map[string]string{"password": "newpass123"}), http.StatusForbidden)
	mustCode(t, e.do("PATCH", "/api/v1/admin/admins/"+id2, e.su, map[string]string{"password": "newpass123"}), http.StatusOK)
	if login("admin2@test", "password123") != http.StatusUnauthorized {
		t.Fatal("old password still works after reset")
	}
	if login("admin2@test", "newpass123") != http.StatusOK {
		t.Fatal("new password does not work after reset")
	}
	mustCode(t, e.do("PATCH", "/api/v1/admin/admins/"+id2, e.su, map[string]string{"status": store.AccountDisabled}), http.StatusOK)
	if login("admin2@test", "newpass123") != http.StatusForbidden {
		t.Fatal("disabled admin still logs in")
	}
	mustCode(t, e.do("PATCH", "/api/v1/admin/admins/"+id2, e.su, map[string]string{"status": store.AccountActive}), http.StatusOK)
	if login("admin2@test", "newpass123") != http.StatusOK {
		t.Fatal("re-enabled admin cannot log in")
	}

	// DELETE — super admin only
	mustCode(t, e.do("DELETE", "/api/v1/admin/admins/"+id2, admin, nil), http.StatusForbidden)
	mustCode(t, e.do("DELETE", "/api/v1/admin/admins/"+id2, e.su, nil), http.StatusOK)
	if login("admin2@test", "newpass123") != http.StatusUnauthorized {
		t.Fatal("deleted admin can still log in")
	}

	// the client-account routes refuse an admin target
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+adminID(t, e, "admin@test")+"/disable", e.su, nil), http.StatusForbidden)

	// the super admin itself is locked everywhere
	su := adminID(t, e, "_su@test")
	mustCode(t, e.do("PATCH", "/api/v1/admin/admins/"+su, e.su, map[string]string{"status": store.AccountDisabled}), http.StatusForbidden)
	mustCode(t, e.do("DELETE", "/api/v1/admin/admins/"+su, e.su, nil), http.StatusNotFound) // hDeleteAdmin only touches RoleAdmin
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+su+"/disable", e.su, nil), http.StatusForbidden)
}

// adminID resolves an account id by username from the super-admin roster.
func adminID(t *testing.T, e *env, username string) string {
	t.Helper()
	for _, a := range jbody(t, e.do("GET", "/api/v1/admin/admins", e.su, nil))["admins"].([]any) {
		if m := a.(map[string]any); m["username"] == username {
			return m["account_id"].(string)
		}
	}
	t.Fatalf("admin %q not in roster", username)
	return ""
}

func TestAccountDisableCascadesRevocation(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")

	// sign + submit a document so there is a public record to check later
	pid := e.reserve(user, d.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d, pid)), http.StatusOK)

	// resolve the account id from the admin account list
	var accID string
	for _, a := range jbody(t, e.do("GET", "/api/v1/admin/accounts", admin, nil))["accounts"].([]any) {
		if m := a.(map[string]any); m["email"] == "user@test" {
			accID = m["account_id"].(string)
		}
	}
	if accID == "" {
		t.Fatal("user account not found in admin list")
	}

	w := e.do("POST", "/api/v1/admin/accounts/"+accID+"/disable", admin, nil)
	mustCode(t, w, http.StatusOK)
	if n := jbody(t, w)["certificates_revoked"]; n != float64(1) {
		t.Fatalf("certificates_revoked = %v, want 1", n)
	}

	// the public record now reports the certificate as revoked
	w = e.do("GET", "/api/v1/public/signatures/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if got := jbody(t, w)["certificate_status"]; got != "revoked" {
		t.Fatalf("certificate_status = %v, want revoked", got)
	}

	// the disabled user can no longer log in or reserve
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{
		"email": "user@test", "password": "password123",
	}), http.StatusForbidden)
}

func TestAccountListAndProfile(t *testing.T) {
	e := newEnv(t)
	admin := e.account("admin@test", store.RoleAdmin)

	reg := jbody(t, e.do("POST", "/api/v1/auth/register", "", map[string]string{
		"email": "c@test", "password": "password123", "full_name": "C Orig", "organization": "Org A",
	}))
	id := reg["account_id"].(string)

	w := e.do("PATCH", "/api/v1/admin/accounts/"+id, admin, map[string]string{
		"full_name": "C Updated", "organization": "Org B",
	})
	mustCode(t, w, http.StatusOK)
	got := jbody(t, w)
	if got["full_name"] != "C Updated" || got["organization"] != "Org B" {
		t.Fatalf("profile not updated: %s", w.Body.String())
	}

	list := jbody(t, e.do("GET", "/api/v1/admin/accounts", admin, nil))["accounts"].([]any)
	if len(list) < 2 {
		t.Fatalf("account list too short: %v", list)
	}
}
