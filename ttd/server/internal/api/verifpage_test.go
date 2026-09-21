package api_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"

	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// The standalone verification service (PQC_VERIFY_ADDR) exposes ONLY the
// upload page + verify API + QR pages + public CA material — nothing that
// needs a login, and no signing or admin routes.
func TestVerifyOnlyService(t *testing.T) {
	root, _ := labpki.NewRootCA("Test Root", 10*365*24*time.Hour)
	inter, _ := labpki.NewIntermediateCA(root, "Test Intermediate", 5*365*24*time.Hour)
	srv, err := api.New(store.NewMemory(), api.Config{
		RootCAPEM: labpki.CertPEM(root.Cert), CAChainPEM: labpki.ChainPEM(inter.Cert, root.Cert),
		JWTSecret: []byte("test-secret-0123456789"), PublicBaseURL: "https://verify.test",
		RateLimits: &api.RateLimits{},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.VerifyRoutes()

	call := func(method, path string, body *bytes.Buffer, ct string) *httptest.ResponseRecorder {
		var r *http.Request
		if body != nil {
			r = httptest.NewRequest(method, path, body)
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// landing page
	w := call("GET", "/", nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Verifikasi Dokumen") || !strings.Contains(w.Body.String(), "/api/v1/verify") {
		t.Fatalf("home page: %d %s", w.Code, w.Body.String()[:min(200, w.Body.Len())])
	}
	// upload is the only entry point on the home page; the ID box was removed.
	if b := w.Body.String(); !strings.Contains(b, "Unggah berkas PDF") || !strings.Contains(b, "Alamat server verifikasi") {
		t.Fatalf("home page should carry the upload dropzone + server-address bar")
	}
	if strings.Contains(w.Body.String(), "masukkan ID verifikasi") {
		t.Fatalf("home page should no longer offer the manual ID box")
	}

	// verify route exists (garbage -> 400, not 404)
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	fw, _ := mw.CreateFormFile("file", "x.pdf")
	_, _ = fw.Write([]byte("not a pdf"))
	_ = mw.Close()
	if code := call("POST", "/api/v1/verify", &mb, mw.FormDataContentType()).Code; code == 404 {
		t.Fatalf("/api/v1/verify missing on verify service")
	}

	// public CA material is served
	if call("GET", "/api/v1/public/ca/root.crt", nil, "").Code != 200 {
		t.Fatalf("root.crt not served")
	}

	// the QR scan resolver renders for ANY id (no store lookup) and carries
	// the server-address control + a link to /v/{id}
	sr := call("GET", "/s/sig_anything", nil, "")
	if sr.Code != 200 || !strings.Contains(sr.Body.String(), "Alamat server") ||
		!strings.Contains(sr.Body.String(), "sig_anything") {
		t.Fatalf("scan resolver: %d %s", sr.Code, sr.Body.String()[:min(200, sr.Body.Len())])
	}

	// signing / auth / admin routes are ABSENT
	for _, p := range []struct{ m, path string }{
		{"POST", "/api/v1/auth/register"}, {"POST", "/api/v1/auth/login"},
		{"POST", "/api/v1/signatures/reserve"}, {"GET", "/api/v1/me/signatures"},
		{"GET", "/admin"}, {"GET", "/api/v1/admin/accounts"},
	} {
		if code := call(p.m, p.path, nil, "").Code; code != 404 {
			t.Errorf("%s %s should be 404 on the verify-only service, got %d", p.m, p.path, code)
		}
	}
}

// RB-2c: the server stamps a QR onto a chosen spot (POST .../stamp); the
// client signs what comes back. The result passes strict re-verification and
// the public verifier, and the page count is UNCHANGED (no extra page).
func TestStampThenSubmit(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")

	w := e.do("POST", "/api/v1/signatures/reserve", user, map[string]string{
		"device_id": d.id, "file_name": "x.pdf",
	})
	mustCode(t, w, http.StatusCreated)
	pid := jbody(t, w)["public_id"].(string)

	// stamp: same page count as the original
	before, _ := pdfcpu.PageCount(bytes.NewReader(testpdf.Sample()), nil)
	w = e.do("POST", "/api/v1/signatures/"+pid+"/stamp?page=1&x=0.55&y=0.75&w=0.3", user, testpdf.Sample())
	mustCode(t, w, http.StatusOK)
	stamped := w.Body.Bytes()
	if w.Header().Get("X-QR-Stamp") != "applied" {
		t.Fatalf("missing X-QR-Stamp header")
	}
	after, err := pdfcpu.PageCount(bytes.NewReader(stamped), nil)
	if err != nil {
		t.Fatalf("page count: %v", err)
	}
	if after != before {
		t.Fatalf("pages: before=%d after=%d, want unchanged", before, after)
	}

	signed := e.stampAndSign(user, d, pid) // signs a fresh stamped copy
	w = e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["status"] != "accepted" {
		t.Fatalf("submit not accepted: %s", w.Body.String())
	}

	w = e.verifyMultipart(signed)
	mustCode(t, w, http.StatusOK)
	vb := jbody(t, w)
	if vb["registered"] != true || vb["verification"].(map[string]any)["valid"] != true {
		t.Fatalf("public verify failed: %s", w.Body.String())
	}
}

// §2b: the ?stamps= JSON array places N caption+QR stamps in one call. The
// page count is unchanged, both images are embedded, and the result still
// strict-verifies and registers.
func TestStampMultiPlacement(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	before, _ := pdfcpu.PageCount(bytes.NewReader(testpdf.Sample()), nil)

	const stamps = `[{"page":1,"x":0.55,"y":0.60,"w":0.30},{"page":1,"x":0.08,"y":0.10,"w":0.22}]`

	// one stamp for comparison, then two — the two-stamp PDF must be larger
	// (both images landed) and keep the same page count.
	one := e.do("POST", "/api/v1/signatures/"+pid+"/stamp?stamps="+
		url.QueryEscape(`[{"page":1,"x":0.55,"y":0.60,"w":0.30}]`), user, testpdf.Sample())
	mustCode(t, one, http.StatusOK)

	w := e.do("POST", "/api/v1/signatures/"+pid+"/stamp?reason=Persetujuan&issued_place=Bandung&stamps="+
		url.QueryEscape(stamps), user, testpdf.Sample())
	mustCode(t, w, http.StatusOK)
	if w.Header().Get("X-QR-Stamp") != "applied" {
		t.Fatalf("missing X-QR-Stamp header")
	}
	stamped := w.Body.Bytes()
	if len(stamped) <= one.Body.Len() {
		t.Fatalf("two-stamp PDF (%d B) not larger than one-stamp (%d B)", len(stamped), one.Body.Len())
	}
	after, err := pdfcpu.PageCount(bytes.NewReader(stamped), nil)
	if err != nil {
		t.Fatalf("page count: %v", err)
	}
	if after != before {
		t.Fatalf("pages: before=%d after=%d, want unchanged", before, after)
	}

	// the multi-stamped bytes sign on-device, submit, and pass the public verifier
	res, err := signing.SignPDF(stamped, d.keyPEM, d.chainPEM, signing.Options{
		SignerName: "Tester", PublicID: pid,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	w = e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, res.SignedPDF)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["status"] != "accepted" {
		t.Fatalf("submit not accepted: %s", w.Body.String())
	}
	w = e.verifyMultipart(res.SignedPDF)
	mustCode(t, w, http.StatusOK)
	vb := jbody(t, w)
	if vb["registered"] != true || vb["verification"].(map[string]any)["valid"] != true {
		t.Fatalf("public verify failed: %s", w.Body.String())
	}
}

// the QR landing page (GET /v/{id}) renders the record as HTML, and reports
// "DICABUT" once the certificate is revoked.
func TestQRLandingPage(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d, pid)), http.StatusOK)

	w := e.do("GET", "/v/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	if b := w.Body.String(); !strings.Contains(b, "TERVERIFIKASI") || !strings.Contains(b, "Verifikasi Tanda Tangan") {
		t.Fatalf("landing page missing expected content: %s", b[:min(400, len(b))])
	}
	if b := w.Body.String(); !strings.Contains(b, "/v/"+pid+"/document") || !strings.Contains(b, "Dokumen yang ditandatangani") {
		t.Fatalf("landing page should embed the signed document: %s", b[:min(600, len(b))])
	}
	if b := w.Body.String(); !strings.Contains(b, "Alamat server verifikasi") {
		t.Fatalf("landing page should carry the server-address bar")
	}

	// the authoritative signed PDF is served publicly (no token)
	w = e.do("GET", "/v/"+pid+"/document", "", nil)
	mustCode(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("document content-type = %q", ct)
	}
	if !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
		t.Fatalf("document response is not a PDF")
	}
	mustCode(t, e.do("GET", "/v/sig_does_not_exist/document", "", nil), http.StatusNotFound)

	// unknown id -> 404 HTML, not a JSON error
	w = e.do("GET", "/v/sig_does_not_exist", "", nil)
	mustCode(t, w, http.StatusNotFound)
	if !strings.Contains(w.Body.String(), "Tidak ditemukan") {
		t.Fatalf("unknown-id page: %s", w.Body.String())
	}

	// revoke the cert -> page shows DICABUT
	mustCode(t, e.do("POST", "/api/v1/admin/certificates/"+d.certID+"/revoke", admin,
		map[string]string{"reason": "keyCompromise"}), http.StatusOK)
	w = e.do("GET", "/v/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "DICABUT") {
		t.Fatalf("revoked page should say DICABUT: %s", w.Body.String())
	}
}

// stamp is refused for a reservation the caller does not own and for a
// non-PDF body.
func TestStampGuards(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	other := e.account("intruder@test", store.RoleUser)
	mustCode(t, e.do("POST", "/api/v1/signatures/"+pid+"/stamp", other, testpdf.Sample()), http.StatusNotFound)

	mustCode(t, e.do("POST", "/api/v1/signatures/"+pid+"/stamp", user, []byte("not a pdf")), http.StatusUnprocessableEntity)
}
