package api_test

import (
	"net/http"
	"testing"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Per-account certificate detail (expiry) + renewal, requested after a
// security review noted admins had no way to see a certificate's expiry date
// or renew one without hand-editing IDs.

func TestAccountCertificateListShowsExpiryAndStatus(t *testing.T) {
	e := newEnv(t)
	user := e.account("bob@test", store.RoleUser)
	admin := e.adminTok()
	d := e.enrolledDevice(user, admin, "laptop")

	acct := jbody(t, e.do("GET", "/api/v1/admin/accounts", admin, nil))["accounts"].([]any)
	var accountID string
	for _, a := range acct {
		if a.(map[string]any)["email"] == "bob@test" {
			accountID = a.(map[string]any)["account_id"].(string)
		}
	}
	if accountID == "" {
		t.Fatal("could not find bob@test's account id")
	}

	w := e.do("GET", "/api/v1/admin/accounts/"+accountID+"/certificates", admin, nil)
	mustCode(t, w, http.StatusOK)
	certs := jbody(t, w)["certificates"].([]any)
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d: %v", len(certs), certs)
	}
	c := certs[0].(map[string]any)
	if c["certificate_id"] != d.certID {
		t.Fatalf("certificate_id = %v, want %v", c["certificate_id"], d.certID)
	}
	if c["status"] != store.CertActive {
		t.Fatalf("status = %v, want active", c["status"])
	}
	if c["not_after"] == nil || c["not_after"] == "" {
		t.Fatal("not_after (expiry) missing from certificate view")
	}
	if c["expired"] != false {
		t.Fatalf("a freshly issued 1-year certificate must not read expired: %v", c["expired"])
	}

	// a plain user token cannot list anyone's certificates
	mustCode(t, e.do("GET", "/api/v1/admin/accounts/"+accountID+"/certificates", user, nil), http.StatusForbidden)
}

func TestRenewCertificateIssuesAFreshEnrollmentWithoutTouchingTheOldCertificate(t *testing.T) {
	e := newEnv(t)
	user := e.account("carol@test", store.RoleUser)
	admin := e.adminTok()
	d := e.enrolledDevice(user, admin, "phone")

	acct := jbody(t, e.do("GET", "/api/v1/admin/accounts", admin, nil))["accounts"].([]any)
	var accountID string
	for _, a := range acct {
		if a.(map[string]any)["email"] == "carol@test" {
			accountID = a.(map[string]any)["account_id"].(string)
		}
	}

	w := e.do("POST", "/api/v1/admin/accounts/"+accountID+"/certificates/"+d.certID+"/renew", admin, nil)
	mustCode(t, w, http.StatusCreated)
	rb := jbody(t, w)
	newEnrollID := rb["enrollment_id"].(string)
	if rb["device_id"] != d.id {
		t.Fatalf("renewal device_id = %v, want %v (same device, no re-enrolment on the client)", rb["device_id"], d.id)
	}

	// the new enrollment is pre-approved and reuses the SAME CSR (same device key)
	enrolls := jbody(t, e.do("GET", "/api/v1/admin/enrollments", admin, nil))["enrollments"].([]any)
	var found map[string]any
	for _, en := range enrolls {
		if en.(map[string]any)["enrollment_id"] == newEnrollID {
			found = en.(map[string]any)
		}
	}
	if found == nil {
		t.Fatal("renewal enrollment does not show up in the admin enrollment queue")
	}
	if found["status"] != store.EnrollmentApproved {
		t.Fatalf("renewal enrollment status = %v, want approved (no separate approve step)", found["status"])
	}

	// the OLD certificate must still be untouched/active — renewal is not a revoke
	certs := jbody(t, e.do("GET", "/api/v1/admin/accounts/"+accountID+"/certificates", admin, nil))["certificates"].([]any)
	for _, cv := range certs {
		c := cv.(map[string]any)
		if c["certificate_id"] == d.certID && c["status"] != store.CertActive {
			t.Fatalf("renewing must not revoke the previous certificate, got status %v", c["status"])
		}
	}

	// wrong account id for this cert -> 404, not leaked across accounts
	e.account("dave@test", store.RoleUser)
	accountsAfter := jbody(t, e.do("GET", "/api/v1/admin/accounts", admin, nil))["accounts"].([]any)
	var daveID string
	for _, a := range accountsAfter {
		if a.(map[string]any)["email"] == "dave@test" {
			daveID = a.(map[string]any)["account_id"].(string)
		}
	}
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+daveID+"/certificates/"+d.certID+"/renew", admin, nil), http.StatusNotFound)
}
