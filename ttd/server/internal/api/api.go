// Package api is the PQC PDF Sign V1 receiver HTTP server (Rencana V1 §17).
//
// It accepts already-signed PDFs, re-verifies them strictly against the
// configured Root CA, stores metadata + the object, and serves a public
// verifier. There is deliberately NO endpoint that signs a PDF for a user
// (§1, §17.5).
package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Config wires the server. RootCAPEM is the only trust anchor for submissions
// and verification (§5.3).
type Config struct {
	RootCAPEM      []byte
	CAChainPEM     []byte // Root + Intermediate, served at /public/ca/chain.pem
	CRLPEM         []byte // current CRL; replaceable via /admin/crl/import
	JWTSecret      []byte
	PublicBaseURL  string // e.g. https://verify.example.id
	MaxUploadBytes int64  // absolute request-body ceiling; 0 -> 25 MiB (§24)
	// Large-document tiers (see docs/large-files.md). Each defaults to
	// min(MaxUploadBytes, its own soft cap):
	//   size <= MaxStampBytes   -> server may draw the QR stamp (pdfcpu)
	//   size <= MaxVerifyBytes  -> server strict-verifies on submit
	//   MaxVerifyBytes < size   -> store-only: hash recorded, NOT verified
	MaxStampBytes  int64  // 0 -> min(MaxUploadBytes, 150 MiB)
	MaxVerifyBytes int64  // 0 -> min(MaxUploadBytes, 350 MiB)
	UploadDir      string // resumable-upload scratch dir; "" -> os.TempDir()
	AccessTTL      time.Duration
	Issuer         string // TOTP issuer label; "" -> "PQC PDF Sign"

	// SuperAdminUsername, when non-empty, bootstraps a single super-admin
	// account on startup if none exists (first generate). SuperAdminPassword
	// is used verbatim when set; otherwise a random one is generated and
	// logged once. Leaving Username empty (tests) skips the bootstrap.
	SuperAdminUsername string
	SuperAdminPassword string

	// RateLimits are per-minute caps. nil applies sane defaults; pass
	// &RateLimits{} to disable every bucket (tests do this).
	RateLimits *RateLimits

	// LabIssuer, when non-nil, mounts a DEV-ONLY endpoint
	// (POST /api/v1/admin/enrollments/{id}/issue-lab) that drives the bundled
	// offline ca-admin binary to issue a device certificate straight from an
	// enrollment, so the /admin console is one click. NEVER set this in
	// production — real issuance is air-gapped (docs/pki-ceremony.md).
	LabIssuer *LabIssuer
}

// RateLimits — per-minute request caps (Rencana V1 §24). A zero value
// disables that bucket.
type RateLimits struct {
	LoginPerIP        int
	ReservePerAccount int
	SubmitPerAccount  int
	VerifyPerIP       int
}

func defaultRateLimits() RateLimits {
	return RateLimits{LoginPerIP: 10, ReservePerAccount: 60, SubmitPerAccount: 30, VerifyPerIP: 30}
}

// Store is everything the handlers need from persistence. Both
// store.Memory and store.Postgres satisfy it, so the backend is chosen at
// startup and nothing else in the package changes.
type Store interface {
	CreateAccount(store.Account) (store.Account, error)
	AccountByEmail(string) (store.Account, error)
	Account(string) (store.Account, error)
	ListAccounts() []store.Account
	SetAccountStatus(id, status string) error
	UpdateAccountProfile(id, fullName, org string) error
	SetAccountPassword(id, passwordHash string) error
	DeleteAccount(id string) error

	CreateDevice(store.Device) (store.Device, error)
	Device(string) (store.Device, error)
	SetDeviceStatus(id, status string) error
	DevicesByAccount(string) []store.Device

	CreateEnrollment(store.Enrollment) (store.Enrollment, error)
	Enrollment(string) (store.Enrollment, error)
	ListEnrollments() []store.Enrollment
	SetEnrollmentStatus(id, status string) error

	CreateCertificate(store.Certificate) (store.Certificate, error)
	Certificate(string) (store.Certificate, error)
	CertificateByDevice(string) (store.Certificate, error)
	CertificateBySerial(string) (store.Certificate, error)
	CertificatesByAccount(string) []store.Certificate
	RevokeCertificate(id, reason string) error

	CreateReservation(store.Reservation) (store.Reservation, error)
	Reservation(string) (store.Reservation, error)
	SetReservationStatus(publicID, status string) error

	CreateSignature(store.Signature) (store.Signature, error)
	Signature(string) (store.Signature, error)
	SignaturesByAccount(string) []store.Signature

	PutObject(key string, data []byte) error
	GetObject(key string) ([]byte, error)
	PutObjectFrom(key string, r io.Reader, size int64) error
	OpenObject(key string) (io.ReadCloser, int64, error)

	Append(store.AuditEvent)
	AuditEvents(limit int) []store.AuditEvent
}

type Server struct {
	st      Store
	signer  *auth.Signer
	cfg     Config
	crl     []byte // mutable copy of cfg.CRLPEM
	issuer  string
	uploads *uploadManager

	rlLogin, rlReserve, rlSubmit, rlVerify *limiterSet
}

func New(st Store, cfg Config) (*Server, error) {
	if len(cfg.RootCAPEM) == 0 {
		return nil, errors.New("api: RootCAPEM is required")
	}
	if p := x509.NewCertPool(); !p.AppendCertsFromPEM(cfg.RootCAPEM) {
		return nil, errors.New("api: RootCAPEM has no valid certificate")
	}
	if len(cfg.JWTSecret) < 16 {
		return nil, errors.New("api: JWTSecret must be at least 16 bytes")
	}
	if cfg.MaxUploadBytes == 0 {
		cfg.MaxUploadBytes = 25 << 20
	}
	if cfg.MaxStampBytes <= 0 || cfg.MaxStampBytes > cfg.MaxUploadBytes {
		cfg.MaxStampBytes = min(cfg.MaxUploadBytes, 150<<20)
	}
	if cfg.MaxVerifyBytes <= 0 || cfg.MaxVerifyBytes > cfg.MaxUploadBytes {
		cfg.MaxVerifyBytes = min(cfg.MaxUploadBytes, 350<<20)
	}
	if cfg.MaxVerifyBytes < cfg.MaxStampBytes {
		cfg.MaxVerifyBytes = cfg.MaxStampBytes
	}
	if cfg.UploadDir == "" {
		cfg.UploadDir = os.TempDir()
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "PQC PDF Sign"
	}
	rl := defaultRateLimits()
	if cfg.RateLimits != nil {
		rl = *cfg.RateLimits
	}
	mk := func(perMin int) *limiterSet {
		if perMin <= 0 {
			return nil
		}
		return newLimiterSet(perMin)
	}
	s := &Server{
		st:        st,
		signer:    auth.NewSigner(cfg.JWTSecret, cfg.AccessTTL),
		cfg:       cfg,
		crl:       cfg.CRLPEM,
		issuer:    issuer,
		uploads:   newUploadManager(cfg.UploadDir),
		rlLogin:   mk(rl.LoginPerIP),
		rlReserve: mk(rl.ReservePerAccount),
		rlSubmit:  mk(rl.SubmitPerAccount),
		rlVerify:  mk(rl.VerifyPerIP),
	}
	s.ensureSuperAdmin()
	return s, nil
}

// ensureSuperAdmin bootstraps the single super-admin the first time the server
// runs against an empty database (Rencana: account management). It is a no-op
// once a superadmin row exists, and when cfg.SuperAdminUsername is empty.
func (s *Server) ensureSuperAdmin() {
	u := strings.TrimSpace(s.cfg.SuperAdminUsername)
	if u == "" {
		return
	}
	for _, a := range s.st.ListAccounts() {
		if a.Role == store.RoleSuperAdmin {
			return // already bootstrapped
		}
	}
	pw, generated := s.cfg.SuperAdminPassword, false
	if len(pw) < 8 {
		pw, generated = randToken(15), true
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		log.Printf("api: super-admin bootstrap failed (hash): %v", err)
		return
	}
	if _, err := s.st.CreateAccount(store.Account{
		Email: u, DisplayName: u, Role: store.RoleSuperAdmin, Status: store.AccountActive,
		PasswordHash: hash,
	}); err != nil {
		log.Printf("api: super-admin bootstrap failed: %v", err)
		return
	}
	if generated {
		log.Printf("api: SUPER ADMIN created — username %q  password %q  (shown once — change it after first login)", u, pw)
	} else {
		log.Printf("api: SUPER ADMIN created — username %q (password from PQC_SUPERADMIN_PASSWORD)", u)
	}
}

// randToken returns an unpadded base64url string with n bytes of entropy.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "changeme-" + time.Now().Format("20060102150405")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Routes returns the http.Handler for the whole API.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/auth/register", s.hRegister)
	mux.HandleFunc("POST /api/v1/auth/login", s.limit(s.rlLogin, byIP, s.hLogin))
	mux.HandleFunc("POST /api/v1/devices", s.user(s.hCreateDevice))
	mux.HandleFunc("GET /api/v1/devices", s.user(s.hListDevices))
	mux.HandleFunc("POST /api/v1/devices/{device_id}/csr", s.user(s.hSubmitCSR))
	mux.HandleFunc("GET /api/v1/devices/{device_id}/certificate", s.user(s.hDeviceCertificate))
	mux.HandleFunc("POST /api/v1/devices/{device_id}/report-lost", s.user(s.hReportLost))

	mux.HandleFunc("POST /api/v1/uploads", s.user(s.hUploadCreate))
	mux.HandleFunc("PATCH /api/v1/uploads/{id}", s.user(s.hUploadChunk))
	mux.HandleFunc("GET /api/v1/uploads/{id}", s.user(s.hUploadStatus))

	mux.HandleFunc("POST /api/v1/signatures/reserve", s.user(s.limit(s.rlReserve, byAccount, s.hReserve)))
	mux.HandleFunc("POST /api/v1/signatures/{public_id}/stamp", s.user(s.limit(s.rlSubmit, byAccount, s.hStamp)))
	mux.HandleFunc("PUT /api/v1/signatures/{public_id}/document", s.user(s.limit(s.rlSubmit, byAccount, s.hSubmitDocument)))
	mux.HandleFunc("GET /api/v1/signatures/{public_id}", s.user(s.hGetSignature))
	mux.HandleFunc("GET /api/v1/signatures/{public_id}/download", s.user(s.hDownload))
	mux.HandleFunc("GET /api/v1/me/signatures", s.user(s.hMySignatures))

	mux.HandleFunc("POST /api/v1/verify", s.limit(s.rlVerify, byIP, s.hPublicVerify))
	mux.HandleFunc("GET /api/v1/public/signatures/{public_id}", s.hPublicRecord)
	mux.HandleFunc("GET /s/{public_id}", s.hScanResolver)            // QR target: confirm server address, then -> /v/{id}
	mux.HandleFunc("GET /v/{public_id}", s.hVerifyPage)              // human landing page
	mux.HandleFunc("GET /v/{public_id}/document", s.hPublicDocument) // authoritative signed PDF behind the QR
	mux.HandleFunc("GET /api/v1/public/ca/root.crt", s.pem(func() []byte { return s.cfg.RootCAPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/chain.pem", s.pem(func() []byte { return s.cfg.CAChainPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/crl.pem", s.pem(func() []byte { return s.crl }))

	mux.HandleFunc("GET /api/v1/admin/capabilities", s.admin(s.hCapabilities))

	mux.HandleFunc("GET /api/v1/admin/admins", s.superadmin(s.hListAdmins))
	mux.HandleFunc("POST /api/v1/admin/admins", s.superadmin(s.hCreateAdmin))
	mux.HandleFunc("PATCH /api/v1/admin/admins/{id}", s.superadmin(s.hUpdateAdmin))
	mux.HandleFunc("DELETE /api/v1/admin/admins/{id}", s.superadmin(s.hDeleteAdmin))

	mux.HandleFunc("GET /api/v1/admin/accounts", s.admin(s.hListAccounts))
	mux.HandleFunc("POST /api/v1/admin/accounts/{id}/approve", s.admin(s.hApproveAccount))
	mux.HandleFunc("POST /api/v1/admin/accounts/{id}/disable", s.admin(s.hDisableAccount))
	mux.HandleFunc("POST /api/v1/admin/accounts/{id}/enable", s.admin(s.hEnableAccount))
	mux.HandleFunc("PATCH /api/v1/admin/accounts/{id}", s.admin(s.hUpdateAccount))
	mux.HandleFunc("DELETE /api/v1/admin/accounts/{id}", s.admin(s.hDeleteAccount))

	mux.HandleFunc("GET /api/v1/admin/enrollments", s.admin(s.hListEnrollments))
	mux.HandleFunc("GET /api/v1/admin/enrollments/{id}/export", s.admin(s.hExportEnrollment))
	mux.HandleFunc("POST /api/v1/admin/enrollments/{id}/approve", s.admin(s.hApproveEnrollment))
	mux.HandleFunc("POST /api/v1/admin/enrollments/{id}/certificate", s.admin(s.hIssueCertificate))
	mux.HandleFunc("POST /api/v1/admin/certificates/{id}/revoke", s.admin(s.hRevoke))
	mux.HandleFunc("POST /api/v1/admin/crl/import", s.admin(s.hImportCRL))
	mux.HandleFunc("GET /api/v1/admin/audit-events", s.admin(s.hAudit))
	if s.cfg.LabIssuer != nil {
		mux.HandleFunc("POST /api/v1/admin/enrollments/{id}/issue-lab", s.admin(s.hLabIssue))
	}

	// Static admin console (Rencana V1 §14 operator workflow, in a browser).
	mux.HandleFunc("GET /admin", s.hAdminUI)
	mux.HandleFunc("GET /admin/", s.hAdminUI)

	// Shared Liquid Glass stylesheet + runtime (also mounted on VerifyRoutes).
	s.mountUIKit(mux)

	return mux
}

// hCapabilities lets the /admin console feature-detect optional endpoints and
// learn the caller's role (so the super-admin section only shows for one).
func (s *Server) hCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"lab_issuer": s.cfg.LabIssuer != nil,
		"role":       claims(r).Role,
	})
}

// ---- helpers ----

type ctxKey int

const claimsKey ctxKey = 0

func (s *Server) user(h http.HandlerFunc) http.HandlerFunc  { return s.authed(store.RoleUser, h) }
func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc { return s.authed(store.RoleAdmin, h) }
func (s *Server) superadmin(h http.HandlerFunc) http.HandlerFunc {
	return s.authed(store.RoleSuperAdmin, h)
}

func (s *Server) authed(minRole string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || tok == r.Header.Get("Authorization") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		c, err := s.signer.Parse(tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		switch minRole {
		case store.RoleAdmin:
			// a super admin has every admin capability
			if c.Role != store.RoleAdmin && c.Role != store.RoleSuperAdmin {
				writeErr(w, http.StatusForbidden, "admin only")
				return
			}
		case store.RoleSuperAdmin:
			if c.Role != store.RoleSuperAdmin {
				writeErr(w, http.StatusForbidden, "super admin only")
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), claimsKey, c)))
	}
}

func claims(r *http.Request) auth.Claims {
	c, _ := r.Context().Value(claimsKey).(auth.Claims)
	return c
}

func (s *Server) pem(get func() []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := get()
		if len(b) == 0 {
			writeErr(w, http.StatusNotFound, "not configured")
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(b)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *Server) audit(t string, c auth.Claims, deviceID, result, detail string) {
	s.st.Append(store.AuditEvent{Type: t, AccountID: c.Sub, DeviceID: deviceID, Result: result, Detail: detail})
}

// readBody reads at most max bytes from the request body.
func readBody(r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, max+1))
}

var errTooLarge = errors.New("payload too large")

func withinLimit(b []byte, max int64) error {
	if int64(len(b)) > max {
		return errTooLarge
	}
	return nil
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }
