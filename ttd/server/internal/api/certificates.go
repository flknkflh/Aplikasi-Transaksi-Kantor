package api

import (
	"net/http"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Per-account certificate detail + renewal for the admin console. Until this,
// an admin could only see a certificate COUNT per account (accountView) and
// had to already know a certificate_id (from the audit log or an upload
// response) to revoke one — there was no way to see expiry dates or renew.

func certView(c store.Certificate) map[string]any {
	v := map[string]any{
		"certificate_id": c.ID,
		"enrollment_id":  c.EnrollmentID,
		"device_id":      c.DeviceID,
		"serial":         c.Serial,
		"fingerprint":    c.Fingerprint,
		"status":         c.Status,
		"not_before":     fmtTime(c.NotBefore),
		"not_after":      fmtTime(c.NotAfter),
		"expired":        time.Now().After(c.NotAfter),
	}
	if !c.RevokedAt.IsZero() {
		v["revoked_at"] = fmtTime(c.RevokedAt)
		v["rev_reason"] = c.RevReason
	}
	return v
}

// GET /api/v1/admin/accounts/{id}/certificates
func (s *Server) hListAccountCertificates(w http.ResponseWriter, r *http.Request) {
	a, ok := s.clientTarget(w, r)
	if !ok {
		return
	}
	certs := s.st.CertificatesByAccount(a.ID)
	out := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		out = append(out, certView(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"account_id": a.ID, "certificates": out})
}

// POST /api/v1/admin/accounts/{id}/certificates/{cert_id}/renew
//
// A certificate is an immutable signed document — its NotAfter cannot be
// edited, so "renew" means issuing a FRESH one from the same CSR (the device
// keeps its existing key; nothing on the device side changes) through the
// same enrollment pipeline every certificate already goes through: this
// creates a new, pre-approved enrollment that immediately shows up in the
// Perangkat view for the admin to export/sign/upload exactly like any other.
//
// The OLD certificate is deliberately left untouched (still "active", not
// revoked): renewal is routine hygiene, not a compromise/loss event, and the
// server's own strict verification refuses anything not status=active
// (verify.go) — revoking the old one here would retroactively invalidate
// every signature it already made. CertificateByDevice already picks the
// certificate with the latest NotBefore, so the new one becomes "the"
// certificate for future signing the moment it is issued, with no other
// code changes required.
func (s *Server) hRenewCertificate(w http.ResponseWriter, r *http.Request) {
	a, ok := s.clientTarget(w, r)
	if !ok {
		return
	}
	c, err := s.st.Certificate(r.PathValue("cert_id"))
	if err != nil || c.AccountID != a.ID {
		writeErr(w, http.StatusNotFound, "sertifikat tidak ditemukan")
		return
	}
	old, err := s.st.Enrollment(c.EnrollmentID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "data pendaftaran asal tidak ditemukan")
		return
	}
	e, err := s.st.CreateEnrollment(store.Enrollment{
		DeviceID: old.DeviceID, AccountID: a.ID, CSRPEM: old.CSRPEM, CSRKeyFP: old.CSRKeyFP,
		Status: store.EnrollmentApproved, // admin-initiated for an account they already manage — no separate approval step
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal membuat pendaftaran perpanjangan")
		return
	}
	s.st.Append(store.AuditEvent{Type: "certificate.renew", AccountID: a.ID, DeviceID: old.DeviceID,
		Result: "ok", Detail: "dari " + c.ID + " -> pendaftaran " + e.ID})
	writeJSON(w, http.StatusCreated, map[string]any{
		"enrollment_id": e.ID,
		"device_id":     e.DeviceID,
		"renewed_from":  c.ID,
		"note":          "Lanjutkan di tab Perangkat: unduh CSR, terbitkan lewat CA, lalu unggah sertifikat baru.",
	})
}
