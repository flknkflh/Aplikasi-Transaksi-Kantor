package api

import (
	"net/http"
	"strings"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Admin account CRUD (Rencana RB-1). The admin's job in the new model is
// account lifecycle: approve pending registrations, and disable/delete
// accounts — which cascades to every device certificate the account holds so
// that all of that person's past signatures immediately read "revoked" in the
// public verifier.

func (s *Server) accountView(a store.Account) map[string]any {
	certs := s.st.CertificatesByAccount(a.ID)
	active := 0
	for _, c := range certs {
		if c.Status == store.CertActive {
			active++
		}
	}
	return map[string]any{
		"account_id":          a.ID,
		"email":               a.Email,
		"username":            a.Email, // the login identifier; "username" for admin rows
		"full_name":           a.FullName,
		"organization":        a.Organization,
		"role":                a.Role,
		"status":              a.Status,
		"created_at":          fmtTime(a.CreatedAt),
		"certificates":        len(certs),
		"active_certificates": active,
	}
}

// hCreateAdmin (super admin only): create an active admin from a username +
// password. Admins can no longer self-register.
func (s *Server) hCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"` // alias for username
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	u := strings.TrimSpace(in.Username)
	if u == "" {
		u = strings.TrimSpace(in.Email)
	}
	if u == "" || len(in.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "username dan kata sandi minimal 8 karakter wajib diisi")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash")
		return
	}
	a, err := s.st.CreateAccount(store.Account{
		Email: u, DisplayName: u, Role: store.RoleAdmin, Status: store.AccountActive,
		PasswordHash: hash,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.st.Append(store.AuditEvent{Type: "admin.create", AccountID: a.ID, Result: "ok", Detail: claims(r).Sub})
	writeJSON(w, http.StatusCreated, s.accountView(a))
}

// hListAdmins (super admin only): the admin roster for the SU console.
func (s *Server) hListAdmins(w http.ResponseWriter, r *http.Request) {
	me := claims(r).Sub
	out := []map[string]any{}
	for _, a := range s.st.ListAccounts() {
		if a.Role != store.RoleAdmin && a.Role != store.RoleSuperAdmin {
			continue
		}
		out = append(out, map[string]any{
			"account_id": a.ID,
			"username":   a.Email,
			"role":       a.Role,
			"status":     a.Status,
			"self":       a.ID == me,
			"created_at": fmtTime(a.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": out})
}

// hUpdateAdmin (super admin only): PATCH /api/v1/admin/admins/{id}.
// {"password":"..."} resets the password; {"status":"active"|"disabled"}
// toggles login. The super-admin row itself cannot be changed here.
func (s *Server) hUpdateAdmin(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.Account(r.PathValue("id"))
	if err != nil || (a.Role != store.RoleAdmin && a.Role != store.RoleSuperAdmin) {
		writeErr(w, http.StatusNotFound, "admin tidak ditemukan")
		return
	}
	if a.Role == store.RoleSuperAdmin {
		writeErr(w, http.StatusForbidden, "akun super admin tidak bisa diubah dari sini")
		return
	}
	var in struct {
		Password string `json:"password"`
		Status   string `json:"status"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if in.Password != "" {
		if len(in.Password) < 8 {
			writeErr(w, http.StatusBadRequest, "kata sandi minimal 8 karakter")
			return
		}
		hash, herr := auth.HashPassword(in.Password)
		if herr != nil {
			writeErr(w, http.StatusInternalServerError, "hash")
			return
		}
		if e := s.st.SetAccountPassword(a.ID, hash); e != nil {
			writeErr(w, http.StatusInternalServerError, "update")
			return
		}
		s.st.Append(store.AuditEvent{Type: "admin.password", AccountID: a.ID, Result: "ok", Detail: claims(r).Sub})
	}
	switch in.Status {
	case store.AccountActive, store.AccountDisabled:
		if e := s.st.SetAccountStatus(a.ID, in.Status); e != nil {
			writeErr(w, http.StatusInternalServerError, "update")
			return
		}
		s.st.Append(store.AuditEvent{Type: "admin.status", AccountID: a.ID, Result: "ok", Detail: in.Status})
	case "":
		// nothing
	default:
		writeErr(w, http.StatusBadRequest, "status harus active atau disabled")
		return
	}
	na, _ := s.st.Account(a.ID)
	writeJSON(w, http.StatusOK, s.accountView(na))
}

// hDeleteAdmin (super admin only): DELETE /api/v1/admin/admins/{id}.
func (s *Server) hDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.Account(r.PathValue("id"))
	if err != nil || a.Role != store.RoleAdmin {
		writeErr(w, http.StatusNotFound, "admin tidak ditemukan")
		return
	}
	if err := s.st.DeleteAccount(a.ID); err != nil {
		_ = s.st.SetAccountStatus(a.ID, store.AccountDisabled)
		s.st.Append(store.AuditEvent{Type: "admin.delete", AccountID: a.ID, Result: "tombstone"})
		writeJSON(w, http.StatusOK, map[string]any{
			"account_id": a.ID, "status": store.AccountDisabled,
			"note": "akun masih dirujuk; dinonaktifkan permanen alih-alih dihapus",
		})
		return
	}
	s.st.Append(store.AuditEvent{Type: "admin.delete", AccountID: a.ID, Result: "ok", Detail: claims(r).Sub})
	writeJSON(w, http.StatusOK, map[string]any{"account_id": a.ID, "status": "deleted"})
}

// clientTarget loads the account for a /admin/accounts/{id} route and refuses
// anything that is not a plain end user. Admin accounts are managed only via
// the super-admin "Admin" menu (/api/v1/admin/admins).
func (s *Server) clientTarget(w http.ResponseWriter, r *http.Request) (store.Account, bool) {
	a, err := s.st.Account(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return store.Account{}, false
	}
	if a.Role != store.RoleUser {
		writeErr(w, http.StatusForbidden, "akun admin dikelola di menu Admin (khusus super admin)")
		return store.Account{}, false
	}
	return a, true
}

func (s *Server) hListAccounts(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, a := range s.st.ListAccounts() {
		out = append(out, s.accountView(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

func (s *Server) hApproveAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.clientTarget(w, r)
	if !ok {
		return
	}
	if a.Status == store.AccountActive {
		writeJSON(w, http.StatusOK, s.accountView(a))
		return
	}
	if err := s.st.SetAccountStatus(a.ID, store.AccountActive); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.approve", AccountID: a.ID, Result: "ok"})
	a, _ = s.st.Account(a.ID)
	writeJSON(w, http.StatusOK, s.accountView(a))
}

func (s *Server) hEnableAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.clientTarget(w, r)
	if !ok {
		return
	}
	if err := s.st.SetAccountStatus(a.ID, store.AccountActive); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.enable", AccountID: a.ID, Result: "ok",
		Detail: "prior certificates stay revoked; the user re-enrols on next login"})
	a, _ = s.st.Account(a.ID)
	writeJSON(w, http.StatusOK, s.accountView(a))
}

func (s *Server) hUpdateAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.clientTarget(w, r)
	if !ok {
		return
	}
	var in struct {
		FullName     string `json:"full_name"`
		Organization string `json:"organization"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if err := s.st.UpdateAccountProfile(a.ID, in.FullName, in.Organization); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.update", AccountID: a.ID, Result: "ok"})
	a, _ = s.st.Account(a.ID)
	writeJSON(w, http.StatusOK, s.accountView(a))
}

// disableCascade revokes every active certificate of an account and publishes
// a fresh CRL. Returns the number of certificates revoked.
func (s *Server) disableCascade(r *http.Request, accountID, reason string) int {
	n := 0
	for _, c := range s.st.CertificatesByAccount(accountID) {
		if c.Status != store.CertActive {
			continue
		}
		_ = s.st.RevokeCertificate(c.ID, reason)
		_ = s.revokeViaCA(r.Context(), c.Serial, "cessationOfOperation")
		for _, d := range s.st.DevicesByAccount(accountID) {
			if d.ID == c.DeviceID {
				_ = s.st.SetDeviceStatus(d.ID, store.DeviceLost)
			}
		}
		s.st.Append(store.AuditEvent{Type: "certificate.revoke", AccountID: accountID,
			DeviceID: c.DeviceID, Result: "ok", Detail: c.Serial + " " + reason})
		n++
	}
	if n > 0 {
		if crl, err := s.publishCRLViaCA(r.Context()); err == nil && len(crl) > 0 {
			s.crl = crl
			s.st.Append(store.AuditEvent{Type: "crl.publish", AccountID: accountID, Result: "ok"})
		}
	}
	return n
}

func (s *Server) hDisableAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.clientTarget(w, r)
	if !ok {
		return
	}
	id := a.ID
	_ = s.st.SetAccountStatus(id, store.AccountDisabled)
	revoked := s.disableCascade(r, id, "account disabled")
	s.st.Append(store.AuditEvent{Type: "account.disable", AccountID: id, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"account_id": id, "status": store.AccountDisabled, "certificates_revoked": revoked,
	})
}

func (s *Server) hDeleteAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.clientTarget(w, r)
	if !ok {
		return
	}
	id := a.ID
	_ = s.st.SetAccountStatus(id, store.AccountDisabled)
	revoked := s.disableCascade(r, id, "account deleted")
	// True row deletion only succeeds when nothing references the account
	// (no signatures/devices). Signatures are legal records, so a used
	// account is kept as a disabled tombstone instead.
	if err := s.st.DeleteAccount(id); err != nil {
		s.st.Append(store.AuditEvent{Type: "account.delete", AccountID: id, Result: "tombstone"})
		writeJSON(w, http.StatusOK, map[string]any{
			"account_id": id, "status": store.AccountDisabled, "certificates_revoked": revoked,
			"note": "akun punya riwayat tanda tangan; dinonaktifkan permanen alih-alih dihapus",
		})
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.delete", AccountID: id, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"account_id": id, "status": "deleted", "certificates_revoked": revoked,
	})
}
