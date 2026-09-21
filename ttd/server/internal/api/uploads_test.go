package api_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// A signed PDF can be pushed in chunks to a resumable upload, then submitted
// by pointing PUT .../document at it with ?upload_id=. The verified-tier logic
// is unchanged.
func TestResumableUploadSubmit(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	signed := signWith(t, d, pid)

	w := e.do("POST", "/api/v1/uploads", user, nil)
	mustCode(t, w, http.StatusCreated)
	upID := jbody(t, w)["upload_id"].(string)

	half := len(signed) / 2
	w = e.do("PATCH", "/api/v1/uploads/"+upID+"?offset=0", user, signed[:half])
	mustCode(t, w, http.StatusOK)
	if got := int(jbody(t, w)["received"].(float64)); got != half {
		t.Fatalf("received after chunk 1 = %d, want %d", got, half)
	}
	// a wrong offset is a conflict, not silent corruption
	mustCode(t, e.do("PATCH", "/api/v1/uploads/"+upID+"?offset=0", user, signed[half:]), http.StatusConflict)

	w = e.do("PATCH", "/api/v1/uploads/"+upID+"?offset="+strconv.Itoa(half), user, signed[half:])
	mustCode(t, w, http.StatusOK)
	if got := int(jbody(t, w)["received"].(float64)); got != len(signed) {
		t.Fatalf("received after chunk 2 = %d, want %d", got, len(signed))
	}

	w = e.do("PUT", "/api/v1/signatures/"+pid+"/document?upload_id="+upID, user, nil)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["status"] != "accepted" {
		t.Fatalf("submit not accepted: %s", w.Body.String())
	}
	// the upload session is consumed
	mustCode(t, e.do("GET", "/api/v1/uploads/"+upID, user, nil), http.StatusNotFound)

	w = e.verifyMultipart(signed)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["registered"] != true {
		t.Fatalf("not registered: %s", w.Body.String())
	}
}

// Above MaxVerifyBytes the server cannot verify in memory: it records the
// SHA-512 and stores the file, and the public record says so.
func TestStoreOnlyLargeSubmit(t *testing.T) {
	e := newEnvWith(t, func(c *api.Config) {
		c.MaxUploadBytes = 8 << 20
		c.MaxStampBytes = 1 << 10
		c.MaxVerifyBytes = 1 << 10 // ~1 KiB: the sample signed PDF is bigger
	})
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	signed := signWith(t, d, pid)
	if len(signed) <= 1<<10 {
		t.Skip("sample signed PDF unexpectedly tiny")
	}

	w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
	mustCode(t, w, http.StatusOK)
	b := jbody(t, w)
	if b["status"] != "stored_unverified" || b["verification_status"] != store.VerificationStoredOnly {
		t.Fatalf("want stored_unverified, got %s", w.Body.String())
	}
	if s, _ := b["signed_pdf_sha512"].(string); s == "" {
		t.Fatalf("missing sha512 in store-only result: %s", w.Body.String())
	}

	rec := jbody(t, e.do("GET", "/api/v1/public/signatures/"+pid, "", nil))
	if rec["certificate_status"] != "not_server_verified" || rec["verification_status"] != store.VerificationStoredOnly {
		t.Fatalf("public record: %v", rec)
	}
	w = e.do("GET", "/v/"+pid+"/document", "", nil)
	mustCode(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("stored doc content-type = %q", ct)
	}

	// the human /v/{id} landing page calls it out (web, apk and exe all key off
	// certificate_status / verification_status)
	w = e.do("GET", "/v/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if body := w.Body.String(); !contains(body, "TIDAK DIVERIFIKASI SERVER") {
		t.Fatalf("/v landing page missing the store-only badge")
	}

	// POST /api/v1/verify still runs the crypto on the uploaded bytes and its
	// record carries verification_status so every client can show the marker
	vb := jbody(t, e.verifyMultipart(signed))
	if vb["registered"] != true {
		t.Fatalf("verify: not registered: %s", mustJSONString(vb))
	}
	vr, _ := vb["record"].(map[string]any)
	if vr == nil || vr["verification_status"] != store.VerificationStoredOnly {
		t.Fatalf("verify record missing verification_status: %s", mustJSONString(vb))
	}
}

func mustJSONString(v any) string { b, _ := json.Marshal(v); return string(b) }

// A PDF larger than MaxStampBytes is refused by /stamp (pdfcpu can't stream).
func TestStampTooLargeRejected(t *testing.T) {
	e := newEnvWith(t, func(c *api.Config) {
		c.MaxUploadBytes = 8 << 20
		c.MaxStampBytes = 1 << 10 // ~1 KiB
	})
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	w := e.do("POST", "/api/v1/signatures/"+pid+"/stamp?x=0.6&y=0.8&w=0.3", user, testpdf.Sample())
	mustCode(t, w, http.StatusRequestEntityTooLarge)
}
