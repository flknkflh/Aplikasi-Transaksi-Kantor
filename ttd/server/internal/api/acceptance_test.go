package api_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

func serialOf(t *testing.T, chainPEM []byte) string {
	t.Helper()
	blk, _ := pem.Decode(chainPEM)
	if blk == nil {
		t.Fatal("no PEM in chain")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", c.SerialNumber)
}

// These cover the Rencana V1 §25 acceptance items that the receiver is
// responsible for and that TestHappyPath / TestSubmissionRejections /
// existing tests don't already exercise. docs/acceptance-v1.md maps every
// §25 checkbox to its check.

// §25.6 — revoking one device's certificate must not disable the account's
// other device; the revoked device cannot make new reservations; a signature
// made before revocation stays readable with a "revoked" status.
func TestAcceptance_DeviceLossIsolation(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	win := e.enrolledDevice(user, admin, "Windows Laptop")
	andr := e.enrolledDevice(user, admin, "Android Phone")

	// a signature from the Windows device, before anything is revoked
	pid := e.reserve(user, win.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, win, pid)), http.StatusOK)

	// revoke ONLY the Windows device certificate
	mustCode(t, e.do("POST", "/api/v1/admin/certificates/"+win.certID+"/revoke", admin,
		map[string]string{"reason": "keyCompromise"}), http.StatusOK)

	// Windows device: no new reservation
	mustCode(t, e.do("POST", "/api/v1/signatures/reserve", user,
		map[string]string{"device_id": win.id, "file_name": "x.pdf"}), http.StatusForbidden)

	// Android device: still fully usable
	pid2 := e.reserve(user, andr.id)
	w := e.do("PUT", "/api/v1/signatures/"+pid2+"/document", user, signWith(t, andr, pid2))
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["status"] != "accepted" {
		t.Fatalf("unrelated device blocked: %s", w.Body.String())
	}

	// the historic Windows signature is still readable, now marked revoked
	w = e.do("GET", "/api/v1/public/signatures/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if got := jbody(t, w)["certificate_status"]; got != "revoked" {
		t.Fatalf("public record certificate_status = %v, want revoked", got)
	}
}

// §25.6 — re-enrolment produces a fresh key and a fresh certificate serial.
func TestAcceptance_ReEnrolFreshKeyAndSerial(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)

	d1 := e.enrolledDevice(user, admin, "Laptop")
	d2 := e.enrolledDevice(user, admin, "Laptop (re-enrolled)")

	c1 := serialOf(t, d1.chainPEM)
	c2 := serialOf(t, d2.chainPEM)
	if c1 == c2 {
		t.Fatalf("re-enrolment reused the certificate serial %s", c1)
	}
	// distinct device keys (different signed output for the same input)
	pidA := e.reserve(user, d1.id)
	pidB := e.reserve(user, d2.id)
	if string(signWith(t, d1, pidA)) == string(signWith(t, d2, pidB)) {
		t.Fatal("re-enrolled device produced identical signed bytes — key not fresh")
	}
}

// §25.4 — a certificate belonging to another account is rejected on submit.
func TestAcceptance_DifferentAccountCertificate(t *testing.T) {
	e := newEnv(t)
	admin := e.account("admin@test", store.RoleAdmin)
	alice := e.account("alice@test", store.RoleUser)
	bob := e.account("bob@test", store.RoleUser)

	aliceDev := e.enrolledDevice(alice, admin, "Alice Laptop")
	bobDev := e.enrolledDevice(bob, admin, "Bob Laptop")

	// Bob reserves, then signs with Alice's key + chain.
	pid := e.reserve(bob, bobDev.id)
	w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", bob, signWith(t, aliceDev, pid))
	mustCode(t, w, http.StatusUnprocessableEntity)
	if !contains(w.Body.String(), "different") {
		t.Fatalf("reason = %s", w.Body.String())
	}
}

// §25.5 — the record distinguishes the client-claimed signing time from the
// server-received time; they are separate fields.
func TestAcceptance_ClientTimeVsServerTime(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d, pid)), http.StatusOK)

	rec := jbody(t, e.do("GET", "/api/v1/public/signatures/"+pid, "", nil))
	cc, _ := rec["client_claimed_signing_time"].(string)
	sr, _ := rec["server_received_at"].(string)
	if sr == "" {
		t.Fatal("server_received_at missing")
	}
	if cc == sr {
		t.Fatal("client and server timestamps are the same field/value")
	}
}

// §25.1 — no response body and no audit event may carry private key material.
func TestAcceptance_NoPrivateKeyAnywhere(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d, pid)), http.StatusOK)

	for _, path := range []string{
		"/api/v1/me/signatures",
		"/api/v1/signatures/" + pid,
		"/api/v1/devices",
		"/api/v1/admin/enrollments",
		"/api/v1/admin/audit-events",
	} {
		tok := user
		if strings.Contains(path, "/admin/") {
			tok = admin
		}
		w := e.do("GET", path, tok, nil)
		mustCode(t, w, http.StatusOK)
		if b := strings.ToUpper(w.Body.String()); strings.Contains(b, "PRIVATE KEY") || strings.Contains(b, "BEGIN PRIVATE") {
			t.Fatalf("%s response contains private key material", path)
		}
	}
}
