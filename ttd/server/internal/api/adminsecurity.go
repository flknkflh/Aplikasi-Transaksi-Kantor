package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Admin login hardening (docs/adr/0007-admin-lockout-and-totp.md):
//
//   - Failed-attempt lockout is UNCONDITIONAL for every admin account: five wrong
//     passwords or TOTP codes locks it for 15 minutes (saMaxFailures/saLockFor,
//     the same policy already used for the super admin in superadmin.go).
//   - TOTP is OPT-IN, self-service: an admin turns it on for their own account from
//     the /admin console. It does not touch existing admin accounts (including the
//     demo/seed bootstrap admin) unless they explicitly enable it.
//   - Both share the per-account security row the super admin already uses
//     (store.SuperSecurity, keyed by account id) — no new table. The TOTP secret is
//     sealed under its OWN derived key (adminTOTPAEAD), separate from the super
//     admin's (superadmin.go's totpAEAD), and the login step token is signed with
//     its own key (adminMFAStep) — none of these three are interchangeable with
//     the super admin's equivalents, or with each other's admins' tokens.

const adminMFAStepRole = "admin-totp"

func (s *Server) initAdminMFASigner() {
	s.adminMFAStep = auth.NewSigner(deriveKey(s.cfg.JWTSecret, "pqc-admin-mfa-step/v1"), saStepTTL)
}

// --- sealing an admin's TOTP secret at rest (separate key from the super admin's) ---

func (s *Server) adminTOTPAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKey(s.cfg.JWTSecret, "pqc-admin-totp/v1"))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Server) sealAdminTOTP(secret string) ([]byte, error) {
	aead, err := s.adminTOTPAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(secret), []byte("admin-totp")), nil
}

func (s *Server) openAdminTOTP(sealed []byte) (string, error) {
	aead, err := s.adminTOTPAEAD()
	if err != nil {
		return "", err
	}
	if len(sealed) < aead.NonceSize() {
		return "", errors.New("no secret")
	}
	pt, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte("admin-totp"))
	return string(pt), err
}

// --- shared lockout bookkeeping (hLogin and hLoginTOTP both call these) ---

// adminSecurityFail records one failed password/TOTP attempt and locks the
// account once saMaxFailures is reached. sec must already be loaded for accountID.
func (s *Server) adminSecurityFail(accountID string, sec *store.SuperSecurity) {
	sec.AccountID = accountID
	sec.FailedCount++
	if sec.FailedCount >= saMaxFailures {
		sec.LockedUntil = time.Now().Add(saLockFor)
		sec.FailedCount = 0
		s.st.Append(store.AuditEvent{Type: "admin.lock", AccountID: accountID, Result: "locked"})
	}
	if err := s.st.PutSuperSecurity(*sec); err != nil {
		log.Printf("api: admin failure counter not saved: %v", err)
	}
}

// adminSecuritySuccess clears the failure counter/lockout after a correct
// password or TOTP code. step > 0 also advances the TOTP replay watermark.
func (s *Server) adminSecuritySuccess(accountID string, sec *store.SuperSecurity, step int64) {
	sec.AccountID = accountID
	sec.FailedCount, sec.LockedUntil = 0, time.Time{}
	if step > 0 {
		sec.LastStep = step
	}
	if err := s.st.PutSuperSecurity(*sec); err != nil {
		log.Printf("api: admin security state not saved: %v", err)
	}
}

// --- second login step: TOTP code (only reached when the admin enabled it) ---

// POST /api/v1/auth/login/totp {step_token, code} -> access token
func (s *Server) hLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		StepToken string `json:"step_token"`
		Code      string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	c, err := s.adminMFAStep.Parse(in.StepToken)
	if err != nil || c.Role != adminMFAStepRole {
		writeErr(w, http.StatusUnauthorized, "sesi masuk habis; ulangi dari awal")
		return
	}
	a, err := s.st.Account(c.Sub)
	if err != nil || a.Role != store.RoleAdmin || a.Status != store.AccountActive {
		writeErr(w, http.StatusUnauthorized, "sesi masuk tidak valid")
		return
	}
	sec, _ := s.st.SuperSecurity(a.ID)
	if !sec.TOTPEnabled {
		writeErr(w, http.StatusConflict, "TOTP tidak aktif untuk akun ini")
		return
	}
	if d := time.Until(sec.LockedUntil); d > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "akun dikunci sementara karena terlalu banyak percobaan gagal", "retry_after": int(d.Seconds()),
		})
		return
	}
	secret, err := s.openAdminTOTP(sec.TOTPSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rahasia TOTP tidak terbaca")
		return
	}
	step, ok := auth.VerifyTOTP(secret, in.Code, time.Now(), sec.LastStep)
	if !ok {
		s.adminSecurityFail(a.ID, &sec)
		s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "fail", Detail: "totp"})
		writeErr(w, http.StatusUnauthorized, "kode salah atau sudah dipakai")
		return
	}
	s.adminSecuritySuccess(a.ID, &sec, step)
	s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": s.signer.Issue(a.ID, a.Role),
		"token_type":   "Bearer",
		"expires_in":   int(s.signer.TTL().Seconds()),
	})
}

// --- self-service enrolment (an admin managing their OWN account) ---

// GET /api/v1/admin/security/status
func (s *Server) hAdminSecurityStatus(w http.ResponseWriter, r *http.Request) {
	sec, _ := s.st.SuperSecurity(claims(r).Sub)
	writeJSON(w, http.StatusOK, map[string]any{"totp_enabled": sec.TOTPEnabled})
}

// POST /api/v1/admin/security/totp/begin -> {secret, otpauth_uri, qr_png}
// Generates a new secret and stores it un-enabled; hAdminTOTPConfirm turns it on.
func (s *Server) hAdminTOTPBegin(w http.ResponseWriter, r *http.Request) {
	me := claims(r).Sub
	a, err := s.st.Account(me)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "akun tidak aktif")
		return
	}
	secret := auth.NewTOTPSecret()
	sealed, err := s.sealAdminTOTP(secret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyiapkan TOTP")
		return
	}
	sec, _ := s.st.SuperSecurity(me)
	sec.AccountID, sec.TOTPSecret, sec.TOTPEnabled = me, sealed, false
	if err := s.st.PutSuperSecurity(sec); err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan")
		return
	}
	uri := auth.TOTPURI(s.issuer, a.Email, secret)
	resp := map[string]any{"secret": secret, "otpauth_uri": uri}
	if png, err := qrcode.Encode(uri, qrcode.Medium, 256); err == nil {
		resp["qr_png"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/admin/security/totp/confirm {code} -> turns TOTP on
func (s *Server) hAdminTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	me := claims(r).Sub
	sec, err := s.st.SuperSecurity(me)
	if err != nil || len(sec.TOTPSecret) == 0 || sec.TOTPEnabled {
		writeErr(w, http.StatusConflict, "belum ada pengaturan TOTP yang menunggu konfirmasi")
		return
	}
	secret, err := s.openAdminTOTP(sec.TOTPSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rahasia TOTP tidak terbaca")
		return
	}
	step, ok := auth.VerifyTOTP(secret, in.Code, time.Now(), sec.LastStep)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "kode tidak cocok — periksa jam perangkat dan coba lagi")
		return
	}
	sec.TOTPEnabled, sec.LastStep = true, step
	if err := s.st.PutSuperSecurity(sec); err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan")
		return
	}
	s.st.Append(store.AuditEvent{Type: "admin.totp", AccountID: me, Result: "enrolled"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/admin/security/totp/disable {code} -> turns TOTP off (needs a
// currently-valid code, so a stolen session token alone cannot silently disable it)
func (s *Server) hAdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	me := claims(r).Sub
	sec, err := s.st.SuperSecurity(me)
	if err != nil || !sec.TOTPEnabled {
		writeErr(w, http.StatusConflict, "TOTP tidak aktif")
		return
	}
	secret, err := s.openAdminTOTP(sec.TOTPSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rahasia TOTP tidak terbaca")
		return
	}
	if _, ok := auth.VerifyTOTP(secret, in.Code, time.Now(), sec.LastStep); !ok {
		writeErr(w, http.StatusUnauthorized, "kode tidak cocok")
		return
	}
	sec.TOTPEnabled, sec.TOTPSecret = false, nil
	if err := s.st.PutSuperSecurity(sec); err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan")
		return
	}
	s.st.Append(store.AuditEvent{Type: "admin.totp", AccountID: me, Result: "disabled"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- super-admin recovery path: an admin locked out or who lost their device ---

// POST /api/v1/superadmin/admins/{id}/reset-security (super admin only): clears any
// lockout and disables TOTP. superadmin.go wires this route.
func (s *Server) hResetAdminSecurity(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.Account(r.PathValue("id"))
	if err != nil || a.Role != store.RoleAdmin {
		writeErr(w, http.StatusNotFound, "admin tidak ditemukan")
		return
	}
	if err := s.st.PutSuperSecurity(store.SuperSecurity{AccountID: a.ID}); err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal menyimpan")
		return
	}
	s.st.Append(store.AuditEvent{Type: "admin.security-reset", AccountID: a.ID, Result: "ok", Detail: claims(r).Sub})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
