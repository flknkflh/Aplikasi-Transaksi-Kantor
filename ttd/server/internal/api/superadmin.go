package api

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Super-admin login (docs/adr/0005-superadmin-login.md).
//
// The super admin has ONE job: create, disable, reset and delete admin accounts.
// Its login is deliberately a different mechanism from everyone else's:
//
//   - its own page (/superadmin) and its own endpoints (/api/v1/superadmin/*);
//     the ordinary login refuses it, and it can use nothing outside its own routes;
//   - three steps: password -> (first time: set a new password and enrol an
//     authenticator app) -> a 6-digit TOTP code; without the code there is no session;
//   - its tokens are signed with keys derived separately from the ordinary ones, so an
//     ordinary/admin token can never be replayed here and a super-admin token can never
//     be replayed anywhere else;
//   - short sessions (15 min), a used TOTP code is refused (replay), 5 failures lock the
//     account for 15 minutes, everything is audited.

const (
	saMinPassword    = 12
	saMaxFailures    = 5
	saLockFor        = 15 * time.Minute
	saStepTTL        = 5 * time.Minute
	saStepTOTP       = "totp"  // challenge role: password was right, the code is next
	saStepSetup      = "setup" // challenge role: first login — new password + authenticator enrolment
	saAccessRole     = "superadmin"
	saDefaultSession = 15 * time.Minute
)

func deriveKey(secret []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		panic(err) // only fails for absurd lengths
	}
	return k
}

func (s *Server) initSuperAdminSigners() {
	ttl := s.cfg.SuperAdminSessionTTL
	if ttl <= 0 {
		ttl = saDefaultSession
	}
	s.saStep = auth.NewSigner(deriveKey(s.cfg.JWTSecret, "pqc-sa-step/v1"), saStepTTL)
	s.saAccess = auth.NewSigner(deriveKey(s.cfg.JWTSecret, "pqc-sa-access/v1"), ttl)
}

// --- sealing the TOTP secret at rest ---

func (s *Server) totpAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKey(s.cfg.JWTSecret, "pqc-sa-totp/v1"))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Server) sealTOTP(secret string) ([]byte, error) {
	aead, err := s.totpAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(secret), []byte("superadmin-totp")), nil
}

func (s *Server) openTOTP(sealed []byte) (string, error) {
	aead, err := s.totpAEAD()
	if err != nil {
		return "", err
	}
	if len(sealed) < aead.NonceSize() {
		return "", errors.New("no secret")
	}
	pt, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte("superadmin-totp"))
	return string(pt), err
}

// --- bootstrap ---

// ensureSuperAdmin creates the super admin automatically the first time the
// server runs against a database that has none. There is no built-in password:
// unless PQC_SUPERADMIN_PASSWORD supplies an initial one, a random one is
// generated and printed ONCE in the server log. Either way the first login must
// replace it and enrol an authenticator app.
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
		pw, generated = randToken(18), true
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		log.Printf("api: super-admin bootstrap failed (hash): %v", err)
		return
	}
	acc, err := s.st.CreateAccount(store.Account{
		Email: u, DisplayName: u, Role: store.RoleSuperAdmin, Status: store.AccountActive, PasswordHash: hash,
	})
	if err != nil {
		log.Printf("api: super-admin bootstrap failed: %v", err)
		return
	}
	if err := s.st.PutSuperSecurity(store.SuperSecurity{AccountID: acc.ID, MustChange: true}); err != nil {
		log.Printf("api: super-admin security row could not be written (the first login would not be forced to change the password): %v", err)
	}
	if generated {
		log.Printf("api: SUPER ADMIN dibuat otomatis — buka /superadmin  |  username %q  |  sandi awal %q  (tampil SEKALI; login pertama wajib ganti sandi + daftarkan aplikasi authenticator)", u, pw)
	} else {
		log.Printf("api: SUPER ADMIN dibuat otomatis — buka /superadmin  |  username %q  |  sandi awal dari PQC_SUPERADMIN_PASSWORD (login pertama wajib ganti sandi + daftarkan aplikasi authenticator)", u)
	}
}

// ensureBootstrapAdmin (seeding / development only) creates a first ordinary
// admin from PQC_BOOTSTRAP_ADMIN_EMAIL/PASSWORD when the database has no admin,
// so a fresh demo stack is usable without the interactive super-admin ceremony.
// Real deployments leave both unset and let the super admin create admins.
func (s *Server) ensureBootstrapAdmin() {
	email, pw := strings.TrimSpace(s.cfg.BootstrapAdminEmail), s.cfg.BootstrapAdminPassword
	if email == "" || pw == "" {
		return
	}
	for _, a := range s.st.ListAccounts() {
		if a.Role == store.RoleAdmin {
			return
		}
	}
	if len(pw) < 8 {
		log.Printf("api: PQC_BOOTSTRAP_ADMIN_PASSWORD must be at least 8 characters — no admin created")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return
	}
	if _, err := s.st.CreateAccount(store.Account{Email: email, DisplayName: email, Role: store.RoleAdmin, Status: store.AccountActive, PasswordHash: hash}); err != nil {
		log.Printf("api: bootstrap admin failed: %v", err)
		return
	}
	log.Printf("api: WARNING — bootstrap admin %q created from the environment (seed/dev only; real deployments should create admins from the super-admin page and leave PQC_BOOTSTRAP_ADMIN_* unset)", email)
}

// --- helpers ---

type saAccount struct {
	acct store.Account
	sec  store.SuperSecurity
}

// loadSA loads the super admin behind a challenge/access token subject.
func (s *Server) loadSA(id string) (saAccount, bool) {
	a, err := s.st.Account(id)
	if err != nil || a.Role != store.RoleSuperAdmin || a.Status != store.AccountActive {
		return saAccount{}, false
	}
	sec, err := s.st.SuperSecurity(id)
	if err != nil {
		sec = store.SuperSecurity{AccountID: id}
	}
	return saAccount{a, sec}, true
}

func (s *Server) saLocked(sec store.SuperSecurity) (time.Duration, bool) {
	if d := time.Until(sec.LockedUntil); d > 0 {
		return d, true
	}
	return 0, false
}

func (s *Server) saFail(w http.ResponseWriter, a saAccount, what string) {
	a.sec.FailedCount++
	msg := what
	if a.sec.FailedCount >= saMaxFailures {
		a.sec.LockedUntil = time.Now().Add(saLockFor)
		a.sec.FailedCount = 0
		msg += " — terlalu banyak percobaan gagal, akun dikunci " + saLockFor.String()
		s.st.Append(store.AuditEvent{Type: "superadmin.lock", AccountID: a.acct.ID, Result: "locked"})
	}
	if err := s.st.PutSuperSecurity(a.sec); err != nil {
		log.Printf("api: superadmin failure counter not saved: %v", err)
	}
	s.st.Append(store.AuditEvent{Type: "superadmin.login", AccountID: a.acct.ID, Result: "fail", Detail: what})
	writeErr(w, http.StatusUnauthorized, msg)
}

func (s *Server) saSuccess(w http.ResponseWriter, a saAccount, step int64) {
	a.sec.FailedCount, a.sec.LockedUntil = 0, time.Time{}
	if step > 0 {
		a.sec.LastStep = step
	}
	if err := s.st.PutSuperSecurity(a.sec); err != nil {
		// without the stored step a code could be replayed: do not open a session
		log.Printf("api: superadmin security state not saved: %v", err)
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan status keamanan")
		return
	}
	s.st.Append(store.AuditEvent{Type: "superadmin.login", AccountID: a.acct.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": s.saAccess.Issue(a.acct.ID, saAccessRole), "token_type": "Bearer", "expires_in": int(s.saAccess.TTL().Seconds()),
	})
}

// --- endpoints ---

var dummyHash, _ = auth.HashPassword("no-such-superadmin-placeholder")

// POST /api/v1/superadmin/login {username, password} -> {step, challenge}
func (s *Server) hSALogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	acct, err := s.st.AccountByEmail(strings.TrimSpace(in.Username))
	if err != nil || acct.Role != store.RoleSuperAdmin {
		auth.VerifyPassword(in.Password, dummyHash) // same work whether or not the name exists
		writeErr(w, http.StatusUnauthorized, "nama pengguna atau kata sandi salah")
		return
	}
	a, ok := s.loadSA(acct.ID)
	if !ok {
		writeErr(w, http.StatusForbidden, "akun tidak aktif")
		return
	}
	if d, locked := s.saLocked(a.sec); locked {
		s.st.Append(store.AuditEvent{Type: "superadmin.login", AccountID: a.acct.ID, Result: "locked"})
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "akun dikunci sementara karena terlalu banyak percobaan gagal", "retry_after": int(d.Seconds())})
		return
	}
	if !auth.VerifyPassword(in.Password, a.acct.PasswordHash) {
		s.saFail(w, a, "nama pengguna atau kata sandi salah")
		return
	}
	step := saStepTOTP
	if !a.sec.TOTPEnabled || a.sec.MustChange {
		step = saStepSetup
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"step": step, "must_change": a.sec.MustChange, "challenge": s.saStep.Issue(a.acct.ID, step), "expires_in": int(saStepTTL.Seconds()),
	})
}

// POST /api/v1/superadmin/setup/begin {challenge, new_password} -> {secret, otpauth_uri, qr_png}
func (s *Server) hSASetupBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Challenge   string `json:"challenge"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	c, err := s.saStep.Parse(in.Challenge)
	if err != nil || c.Role != saStepSetup {
		writeErr(w, http.StatusUnauthorized, "sesi pengaturan habis; masuk lagi")
		return
	}
	a, ok := s.loadSA(c.Sub)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "sesi pengaturan habis; masuk lagi")
		return
	}
	if a.sec.MustChange || in.NewPassword != "" {
		if msg := s.checkNewPassword(a, in.NewPassword); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		hash, err := auth.HashPassword(in.NewPassword)
		if err != nil || s.st.SetAccountPassword(a.acct.ID, hash) != nil {
			writeErr(w, http.StatusInternalServerError, "gagal menyimpan sandi")
			return
		}
		a.sec.MustChange = false
		s.st.Append(store.AuditEvent{Type: "superadmin.password", AccountID: a.acct.ID, Result: "ok", Detail: "setup"})
	}
	secret := auth.NewTOTPSecret()
	sealed, err := s.sealTOTP(secret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan rahasia TOTP")
		return
	}
	a.sec.TOTPSecret, a.sec.TOTPEnabled = sealed, false
	if err := s.st.PutSuperSecurity(a.sec); err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan")
		return
	}
	uri := auth.TOTPURI(s.issuer, a.acct.Email, secret)
	resp := map[string]any{"secret": secret, "otpauth_uri": uri}
	if png, err := qrcode.Encode(uri, qrcode.Medium, 256); err == nil {
		resp["qr_png"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) checkNewPassword(a saAccount, pw string) string {
	switch {
	case utf8.RuneCountInString(pw) < saMinPassword:
		return "kata sandi baru minimal 12 karakter"
	case utf8.RuneCountInString(pw) > auth.MaxPasswordLength:
		return "kata sandi baru maksimal 128 karakter"
	case auth.VerifyPassword(pw, a.acct.PasswordHash):
		return "kata sandi baru harus berbeda dari yang lama"
	case strings.EqualFold(pw, a.acct.Email):
		return "kata sandi tidak boleh sama dengan nama pengguna"
	}
	return ""
}

// POST /api/v1/superadmin/setup/confirm {challenge, code} -> access token
func (s *Server) hSASetupConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	c, err := s.saStep.Parse(in.Challenge)
	if err != nil || c.Role != saStepSetup {
		writeErr(w, http.StatusUnauthorized, "sesi pengaturan habis; masuk lagi")
		return
	}
	a, ok := s.loadSA(c.Sub)
	if !ok || a.sec.MustChange || len(a.sec.TOTPSecret) == 0 || a.sec.TOTPEnabled {
		writeErr(w, http.StatusConflict, "urutan pengaturan tidak valid; masuk lagi")
		return
	}
	if _, locked := s.saLocked(a.sec); locked {
		writeErr(w, http.StatusTooManyRequests, "akun dikunci sementara")
		return
	}
	secret, err := s.openTOTP(a.sec.TOTPSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rahasia TOTP tidak terbaca")
		return
	}
	step, ok := auth.VerifyTOTP(secret, in.Code, time.Now(), a.sec.LastStep)
	if !ok {
		s.saFail(w, a, "kode tidak cocok — periksa jam perangkat dan coba lagi")
		return
	}
	a.sec.TOTPEnabled = true
	s.st.Append(store.AuditEvent{Type: "superadmin.totp", AccountID: a.acct.ID, Result: "enrolled"})
	s.saSuccess(w, a, step)
}

// POST /api/v1/superadmin/verify {challenge, code} -> access token
func (s *Server) hSAVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	c, err := s.saStep.Parse(in.Challenge)
	if err != nil || c.Role != saStepTOTP {
		writeErr(w, http.StatusUnauthorized, "sesi masuk habis; ulangi dari awal")
		return
	}
	a, ok := s.loadSA(c.Sub)
	if !ok || !a.sec.TOTPEnabled {
		writeErr(w, http.StatusUnauthorized, "sesi masuk tidak valid")
		return
	}
	if d, locked := s.saLocked(a.sec); locked {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "akun dikunci sementara karena terlalu banyak percobaan gagal", "retry_after": int(d.Seconds())})
		return
	}
	secret, err := s.openTOTP(a.sec.TOTPSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rahasia TOTP tidak terbaca")
		return
	}
	step, ok := auth.VerifyTOTP(secret, in.Code, time.Now(), a.sec.LastStep)
	if !ok {
		s.saFail(w, a, "kode salah atau sudah dipakai")
		return
	}
	s.saSuccess(w, a, step)
}

// superadmin authenticates a request with a super-admin access token — a token
// signed with a key no other login can produce.
func (s *Server) superadmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || tok == r.Header.Get("Authorization") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		c, err := s.saAccess.Parse(tok)
		if err != nil || c.Role != saAccessRole {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if _, ok := s.loadSA(c.Sub); !ok {
			writeErr(w, http.StatusUnauthorized, "akun tidak aktif")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), claimsKey, c)))
	}
}

// GET /api/v1/superadmin/me
func (s *Server) hSAMe(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	a, _ := s.st.Account(c.Sub)
	writeJSON(w, http.StatusOK, map[string]any{"username": a.Email, "expires_at": time.Unix(c.Exp, 0).UTC()})
}

// POST /api/v1/superadmin/change-password {current, new}
func (s *Server) hSAChangePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	a, ok := s.loadSA(claims(r).Sub)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "akun tidak aktif")
		return
	}
	if !auth.VerifyPassword(in.Current, a.acct.PasswordHash) {
		s.st.Append(store.AuditEvent{Type: "superadmin.password", AccountID: a.acct.ID, Result: "fail"})
		writeErr(w, http.StatusForbidden, "kata sandi saat ini salah")
		return
	}
	if msg := s.checkNewPassword(a, in.New); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	hash, err := auth.HashPassword(in.New)
	if err != nil || s.st.SetAccountPassword(a.acct.ID, hash) != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan")
		return
	}
	s.st.Append(store.AuditEvent{Type: "superadmin.password", AccountID: a.acct.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) mountSuperAdmin(mux *http.ServeMux) {
	lim := func(h http.HandlerFunc) http.HandlerFunc { return s.limit(s.rlLogin, byIP, h) }
	mux.HandleFunc("POST /api/v1/superadmin/login", lim(s.hSALogin))
	mux.HandleFunc("POST /api/v1/superadmin/setup/begin", lim(s.hSASetupBegin))
	mux.HandleFunc("POST /api/v1/superadmin/setup/confirm", lim(s.hSASetupConfirm))
	mux.HandleFunc("POST /api/v1/superadmin/verify", lim(s.hSAVerify))
	mux.HandleFunc("GET /api/v1/superadmin/me", s.superadmin(s.hSAMe))
	mux.HandleFunc("POST /api/v1/superadmin/change-password", s.superadmin(s.hSAChangePassword))
	// the only thing a super admin manages: admins
	mux.HandleFunc("GET /api/v1/superadmin/admins", s.superadmin(s.hListAdmins))
	mux.HandleFunc("POST /api/v1/superadmin/admins", s.superadmin(s.hCreateAdmin))
	mux.HandleFunc("PATCH /api/v1/superadmin/admins/{id}", s.superadmin(s.hUpdateAdmin))
	mux.HandleFunc("DELETE /api/v1/superadmin/admins/{id}", s.superadmin(s.hDeleteAdmin))
	// Recovery: an admin locked out, or who lost their authenticator device
	// (adminsecurity.go, docs/adr/0007) — clears the lockout and disables TOTP.
	mux.HandleFunc("POST /api/v1/superadmin/admins/{id}/reset-security", s.superadmin(s.hResetAdminSecurity))
	s.mountSuperAdminPage(mux)
}
