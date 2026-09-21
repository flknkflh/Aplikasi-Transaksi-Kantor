package api_test

import (
	"bytes"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"

	_ "github.com/jackc/pgx/v5/stdlib"

	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// backendStore returns an in-memory store, or a freshly-truncated PostgreSQL
// store when PQC_TEST_DATABASE_URL is set (so the same suite proves both
// backends).
func backendStore(t *testing.T) api.Store {
	t.Helper()
	dsn := os.Getenv("PQC_TEST_DATABASE_URL")
	if dsn == "" {
		return store.NewMemory()
	}
	pg, err := store.OpenPostgres(dsn, nil)
	if err != nil {
		t.Fatalf("open test postgres: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`TRUNCATE signatures, reservations, certificates, enrollments,
		devices, accounts, objects, audit_events RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return pg
}

type env struct {
	t      *testing.T
	h      http.Handler
	inter  *labpki.CA
	su     string // bootstrap super-admin token
	badmin string // alias of su — satisfies every admin route, approves pending users
}

func newEnv(t *testing.T) *env { return newEnvWith(t, nil) }

// newEnvWith is newEnv with a hook to tweak the api.Config before New (large-
// file tier caps, upload dir, ...).
func newEnvWith(t *testing.T, tweak func(*api.Config)) *env {
	t.Helper()
	root, err := labpki.NewRootCA("Test Root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := labpki.NewIntermediateCA(root, "Test Intermediate", 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.Config{
		RootCAPEM:          labpki.CertPEM(root.Cert),
		CAChainPEM:         labpki.ChainPEM(inter.Cert, root.Cert),
		JWTSecret:          []byte("test-secret-0123456789"),
		PublicBaseURL:      "https://verify.test",
		RateLimits:         &api.RateLimits{}, // off; TestRateLimit sets its own
		SuperAdminUsername: "_su@test",
		SuperAdminPassword: "password123",
		UploadDir:          t.TempDir(),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	srv, err := api.New(backendStore(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: srv.Routes(), inter: inter}
	// The super admin is bootstrapped by api.New. It creates every admin and
	// approves every pending user in these tests.
	e.su = e.login("_su@test")
	e.badmin = e.su
	return e
}

// register creates an account and logs in. Admin roles go through the
// super-admin create-admin route; users self-register and are approved by the
// super admin.
func (e *env) register(email, role string) string {
	e.t.Helper()
	if role == store.RoleAdmin || role == store.RoleSuperAdmin {
		mustCode(e.t, e.do("POST", "/api/v1/admin/admins", e.su, map[string]string{
			"username": email, "password": "password123",
		}), http.StatusCreated)
		return e.login(email)
	}
	w := e.do("POST", "/api/v1/auth/register", "", map[string]string{
		"email": email, "password": "password123", "display_name": email,
	})
	mustCode(e.t, w, http.StatusCreated)
	if b := jbody(e.t, w); b["status"] == store.AccountPending {
		id := b["account_id"].(string)
		mustCode(e.t, e.do("POST", "/api/v1/admin/accounts/"+id+"/approve", e.su, nil), http.StatusOK)
	}
	return e.login(email)
}

func (e *env) do(method, path, token string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

func jbody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

func mustCode(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
	}
}

// account registers an account and returns its access token, going through
// the RB-1 approval gate exactly like the console does.
func (e *env) account(email, role string) string {
	e.t.Helper()
	return e.register(email, role)
}

// adminTok returns the bootstrap super-admin token created by newEnv (it
// satisfies every admin route).
func (e *env) adminTok() string { return e.badmin }

func (e *env) login(email string) string {
	e.t.Helper()
	w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": email, "password": "password123"})
	mustCode(e.t, w, http.StatusOK)
	return jbody(e.t, w)["access_token"].(string)
}

type device struct {
	id, certID string
	keyPEM     []byte
	chainPEM   []byte
}

func (e *env) enrolledDevice(userTok, adminTok, label string) device {
	e.t.Helper()
	w := e.do("POST", "/api/v1/devices", userTok, map[string]string{"label": label, "platform": "windows"})
	mustCode(e.t, w, http.StatusCreated)
	deviceID := jbody(e.t, w)["device_id"].(string)

	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "ignored", Platform: "windows"})
	if err != nil {
		e.t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/devices/"+deviceID+"/csr", userTok, csrPEM)
	mustCode(e.t, w, http.StatusCreated)
	enrID := jbody(e.t, w)["enrollment_id"].(string)

	csr, _, _ := enrollment.ParseAndValidateCSR(csrPEM)
	cert, err := e.inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: label, Organization: []string{"Test"}}, Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/admin/enrollments/"+enrID+"/certificate", adminTok, labpki.CertPEM(cert))
	mustCode(e.t, w, http.StatusCreated)
	certID := jbody(e.t, w)["certificate_id"].(string)

	return device{id: deviceID, certID: certID, keyPEM: keyPEM, chainPEM: labpki.ChainPEM(cert, e.inter.Cert)}
}

func (e *env) reserve(userTok, deviceID string) string {
	e.t.Helper()
	w := e.do("POST", "/api/v1/signatures/reserve", userTok, map[string]string{
		"device_id": deviceID, "original_sha512": hashutil.CalculateSHA512(testpdf.Sample()), "file_name": "x.pdf",
	})
	mustCode(e.t, w, http.StatusCreated)
	return jbody(e.t, w)["public_id"].(string)
}

func signWith(t *testing.T, d device, publicID string) []byte {
	t.Helper()
	res, err := signing.SignPDF(testpdf.Sample(), d.keyPEM, d.chainPEM, signing.Options{
		SignerName: "Tester", PublicID: publicID,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return res.SignedPDF
}

// stampAndSign runs the RB-2c flow: upload the original to the server's stamp
// endpoint (with a placement), then sign what comes back on the "device".
func (e *env) stampAndSign(userTok string, d device, publicID string) []byte {
	e.t.Helper()
	w := e.do("POST", "/api/v1/signatures/"+publicID+"/stamp?x=0.6&y=0.78&w=0.28", userTok, testpdf.Sample())
	mustCode(e.t, w, http.StatusOK)
	stamped := w.Body.Bytes()

	res, err := signing.SignPDF(stamped, d.keyPEM, d.chainPEM, signing.Options{
		SignerName: "Tester", PublicID: publicID,
	})
	if err != nil {
		e.t.Fatalf("sign: %v", err)
	}
	return res.SignedPDF
}

func (e *env) verifyMultipart(pdf []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "doc.pdf")
	_, _ = fw.Write(pdf)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/verify", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

// --- tests ---

func TestHappyPath(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")

	mustCode(t, e.do("GET", "/api/v1/devices/"+d.id+"/certificate", user, nil), http.StatusOK)

	pid := e.reserve(user, d.id)
	signed := signWith(t, d, pid)

	w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["status"] != "accepted" {
		t.Fatalf("want accepted: %s", w.Body.String())
	}

	// idempotent
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusOK)

	w = e.do("GET", "/api/v1/public/signatures/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["signer_name"] != "user@test" {
		t.Fatalf("public record: %s", w.Body.String())
	}

	w = e.verifyMultipart(signed)
	mustCode(t, w, http.StatusOK)
	vb := jbody(t, w)
	if vb["registered"] != true {
		t.Fatalf("verify registered=false: %s", w.Body.String())
	}
	if vb["verification"].(map[string]any)["valid"] != true {
		t.Fatalf("verify not valid: %s", w.Body.String())
	}

	// audit trail recorded the key events
	w = e.do("GET", "/api/v1/admin/audit-events", admin, nil)
	mustCode(t, w, http.StatusOK)
	if !contains(w.Body.String(), "signature.submit") || !contains(w.Body.String(), "certificate.issue") {
		t.Fatalf("audit missing events: %s", w.Body.String())
	}
}

func TestSubmissionRejections(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d1 := e.enrolledDevice(user, admin, "Dev1")
	d2 := e.enrolledDevice(user, admin, "Dev2")

	t.Run("tampered PDF", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		signed := signWith(t, d1, pid)
		signed[len(signed)/2] ^= 0xFF
		mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusUnprocessableEntity)
	})

	t.Run("certificate of a different device", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		signed := signWith(t, d2, pid) // Dev2 signed, submitted under Dev1's reservation
		w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
		mustCode(t, w, http.StatusUnprocessableEntity)
		if !contains(w.Body.String(), "different device") {
			t.Fatalf("reason = %s", w.Body.String())
		}
	})

	t.Run("public id mismatch", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		signed := signWith(t, d1, "sig_not_the_reservation")
		w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
		mustCode(t, w, http.StatusUnprocessableEntity)
		if !contains(w.Body.String(), "public id") {
			t.Fatalf("reason = %s", w.Body.String())
		}
	})

	t.Run("revoked certificate", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		mustCode(t, e.do("POST", "/api/v1/admin/certificates/"+d1.certID+"/revoke", admin,
			map[string]string{"reason": "keyCompromise"}), http.StatusOK)
		signed := signWith(t, d1, pid)
		w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
		mustCode(t, w, http.StatusUnprocessableEntity)
		if !contains(w.Body.String(), "revoked") {
			t.Fatalf("reason = %s", w.Body.String())
		}
		// a revoked device cert also blocks new reservations
		mustCode(t, e.do("POST", "/api/v1/signatures/reserve", user,
			map[string]string{"device_id": d1.id, "file_name": "x.pdf"}), http.StatusForbidden)
	})

	t.Run("another account cannot read the record", func(t *testing.T) {
		pid := e.reserve(user, d2.id)
		mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d2, pid)), http.StatusOK)
		other := e.account("intruder@test", store.RoleUser)
		mustCode(t, e.do("GET", "/api/v1/signatures/"+pid, other, nil), http.StatusNotFound)
	})
}

func TestAdminEnrollmentExportAndApprove(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)

	w := e.do("POST", "/api/v1/devices", user, map[string]string{"label": "D", "platform": "windows"})
	mustCode(t, w, http.StatusCreated)
	dev := jbody(t, w)["device_id"].(string)

	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, _ := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "x"})
	w = e.do("POST", "/api/v1/devices/"+dev+"/csr", user, csrPEM)
	mustCode(t, w, http.StatusCreated)
	enrID := jbody(t, w)["enrollment_id"].(string)

	w = e.do("GET", "/api/v1/admin/enrollments/"+enrID+"/export", admin, nil)
	mustCode(t, w, http.StatusOK)
	if !contains(w.Body.String(), "CERTIFICATE REQUEST") {
		t.Fatalf("export did not return a CSR: %s", w.Body.String())
	}
	mustCode(t, e.do("POST", "/api/v1/admin/enrollments/"+enrID+"/approve", admin, nil), http.StatusOK)
	// admin routes require the admin role
	mustCode(t, e.do("GET", "/api/v1/admin/enrollments/"+enrID+"/export", user, nil), http.StatusForbidden)
}

func TestNoSigningEndpoint(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/v1/sign", "/api/v1/users/acct_x/sign"} {
		if w := e.do("POST", p, "", nil); w.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d, must not exist", p, w.Code)
		}
	}
}

func TestAuthGuards(t *testing.T) {
	e := newEnv(t)
	user := e.account("u@test", store.RoleUser)
	mustCode(t, e.do("GET", "/api/v1/devices", "", nil), http.StatusUnauthorized)
	mustCode(t, e.do("GET", "/api/v1/admin/enrollments", user, nil), http.StatusForbidden) // user != admin
	mustCode(t, e.do("GET", "/api/v1/devices", user, nil), http.StatusOK)
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	// small custom limiter just for this test's server
	root, _ := labpki.NewRootCA("RL Root", time.Hour)
	srv, err := api.New(store.NewMemory(), api.Config{
		RootCAPEM:  labpki.CertPEM(root.Cert),
		JWTSecret:  []byte("test-secret-0123456789"),
		RateLimits: &api.RateLimits{LoginPerIP: 6, VerifyPerIP: 6},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = srv.Routes()

	got429 := false
	for i := 0; i < 25; i++ {
		w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "x@y", "password": "nope"})
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("login endpoint never rate-limited after 25 rapid attempts")
	}
}
