package api

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/verification"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// ---- auth ----

func (s *Server) hRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		DisplayName  string `json:"display_name"`
		FullName     string `json:"full_name"`
		Organization string `json:"organization"`
		Position     string `json:"position"`
		NIP          string `json:"nip"`
	}
	if err := decode(r, &in); err != nil || in.Email == "" || len(in.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "email and an 8+ char password are required")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash")
		return
	}
	// Self-registration only ever creates a pending end user. Admin accounts
	// are created by the super admin (POST /api/v1/admin/admins) — nobody can
	// mint themselves an operator account.
	displayName := in.DisplayName
	if displayName == "" {
		displayName = in.FullName
	}
	a, err := s.st.CreateAccount(store.Account{
		Email: in.Email, DisplayName: displayName, FullName: in.FullName, Organization: in.Organization,
		Position: in.Position, NIP: in.NIP,
		PasswordHash: hash, Role: store.RoleUser, Status: store.AccountPending,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.register", AccountID: a.ID, Result: "ok", Detail: a.Status})
	writeJSON(w, http.StatusCreated, map[string]string{
		"account_id": a.ID, "role": a.Role, "status": a.Status,
		"message": "akun dibuat, menunggu persetujuan admin",
	})
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	a, err := s.st.AccountByEmail(in.Email)
	if err != nil || !auth.VerifyPassword(in.Password, a.PasswordHash) {
		s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "fail"})
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Account lifecycle gate (Rencana RB-1): only an admin-approved account
	// may obtain a session.
	switch a.Status {
	case store.AccountPending:
		s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "fail", Detail: "pending"})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "akun menunggu persetujuan admin", "account_status": store.AccountPending,
		})
		return
	case store.AccountDisabled:
		s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "fail", Detail: "disabled"})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "akun dinonaktifkan, hubungi admin", "account_status": store.AccountDisabled,
		})
		return
	}

	s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": s.signer.Issue(a.ID, a.Role),
		"token_type":   "Bearer",
		"expires_in":   int(s.signer.TTL().Seconds()),
	})
}

// ---- devices & enrollment ----

func (s *Server) hCreateDevice(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	var in struct{ Label, Platform string }
	_ = decode(r, &in)
	d, _ := s.st.CreateDevice(store.Device{AccountID: c.Sub, Label: in.Label, Platform: in.Platform})
	s.audit("device.create", c, d.ID, "ok", d.Label)
	writeJSON(w, http.StatusCreated, map[string]string{"device_id": d.ID, "status": d.Status})
}

func (s *Server) hListDevices(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	out := []map[string]any{}
	for _, d := range s.st.DevicesByAccount(c.Sub) {
		row := map[string]any{"device_id": d.ID, "label": d.Label, "platform": d.Platform, "status": d.Status}
		if cert, err := s.st.CertificateByDevice(d.ID); err == nil {
			row["certificate_serial"] = cert.Serial
			row["certificate_status"] = cert.Status
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) deviceOwnedBy(r *http.Request) (store.Device, error) {
	d, err := s.st.Device(r.PathValue("device_id"))
	if err != nil {
		return store.Device{}, err
	}
	if d.AccountID != claims(r).Sub {
		return store.Device{}, errors.New("forbidden")
	}
	return d, nil
}

func (s *Server) hSubmitCSR(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	d, err := s.deviceOwnedBy(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	body, err := readBody(r, 64<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	csr, info, err := enrollment.ParseAndValidateCSR(body)
	if err != nil {
		s.audit("csr.submit", c, d.ID, "reject", err.Error())
		writeErr(w, http.StatusBadRequest, "CSR rejected: "+err.Error())
		return
	}
	_ = csr
	e, _ := s.st.CreateEnrollment(store.Enrollment{
		DeviceID: d.ID, AccountID: c.Sub, CSRPEM: body, CSRKeyFP: info.PublicKeyFP,
	})
	s.audit("csr.submit", c, d.ID, "accept", e.ID)

	// RB-1: for an approved account with an online CA, issue the device
	// certificate right now so the app is ready in a single round-trip. If
	// issuance fails the enrollment stays "submitted" for an admin to retry.
	resp := map[string]any{"enrollment_id": e.ID, "status": e.Status}
	if acc, _ := s.st.Account(c.Sub); s.cfg.LabIssuer != nil && acc.Status == store.AccountActive {
		if leaf, err := s.issueViaCA(r.Context(), e); err != nil {
			s.audit("certificate.issue", c, d.ID, "fail", err.Error())
			resp["note"] = "penerbitan sertifikat tertunda, hubungi admin"
		} else if stored, err := s.bindIssuedCert(e, leaf); err != nil {
			s.audit("certificate.issue", c, d.ID, "fail", err.Error())
			resp["note"] = "penerbitan sertifikat tertunda, hubungi admin"
		} else {
			resp["status"] = store.EnrollmentIssued
			resp["certificate_serial"] = stored.Serial
		}
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) hDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	if _, err := s.deviceOwnedBy(r); err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	cert, err := s.st.CertificateByDevice(r.PathValue("device_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no certificate issued yet")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(cert.PEM)
}

func (s *Server) hReportLost(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	d, err := s.deviceOwnedBy(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	_ = s.st.SetDeviceStatus(d.ID, store.DeviceLost)
	s.audit("device.report_lost", c, d.ID, "ok", "")
	writeJSON(w, http.StatusOK, map[string]string{
		"device_id": d.ID, "status": store.DeviceLost,
		"note": "an admin must now revoke the device certificate and publish a new CRL",
	})
}

// ---- admin: certificate issuance & revocation ----

func (s *Server) hListEnrollments(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, e := range s.st.ListEnrollments() {
		out = append(out, map[string]any{
			"enrollment_id": e.ID, "device_id": e.DeviceID, "account_id": e.AccountID,
			"csr_key_fingerprint": e.CSRKeyFP, "status": e.Status, "created_at": fmtTime(e.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollments": out})
}

// hExportEnrollment returns the raw CSR PEM so the offline CA can sign it
// (Rencana V1 §14 "Ambil enrollment yang disetujui", §17.5).
func (s *Server) hExportEnrollment(w http.ResponseWriter, r *http.Request) {
	e, err := s.st.Enrollment(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "enrollment not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(e.CSRPEM)
}

// hApproveEnrollment marks an enrollment approved for issuance.
func (s *Server) hApproveEnrollment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.st.SetEnrollmentStatus(id, store.EnrollmentApproved); err != nil {
		writeErr(w, http.StatusNotFound, "enrollment not found")
		return
	}
	s.st.Append(store.AuditEvent{Type: "enrollment.approve", Result: "ok", Detail: id})
	writeJSON(w, http.StatusOK, map[string]string{"enrollment_id": id, "status": store.EnrollmentApproved})
}

// hIssueCertificate accepts the certificate an offline CA issued for an
// enrollment, checks it chains to the configured Root CA and that its public
// key matches the CSR, then binds it to the enrollment's account+device.
func (s *Server) hIssueCertificate(w http.ResponseWriter, r *http.Request) {
	e, err := s.st.Enrollment(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "enrollment not found")
		return
	}
	body, err := readBody(r, 64<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	stored, err := s.bindIssuedCert(e, body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"certificate_id": stored.ID, "serial": stored.Serial, "fingerprint": stored.Fingerprint,
	})
}

// bindIssuedCert validates an offline-issued leaf certificate for enrollment e
// — it must chain to the configured Root CA and its public key must match the
// enrolled CSR — then records it as the active certificate for e's
// account+device. Shared by hIssueCertificate (admin uploads the PEM) and the
// dev-only lab issuer (hLabIssue drives ca-admin and passes the PEM here).
func (s *Server) bindIssuedCert(e store.Enrollment, leafPEM []byte) (store.Certificate, error) {
	cert, info, err := certutil.ParseAndValidateCertificate(leafPEM, time.Now())
	if err != nil {
		return store.Certificate{}, errors.New("certificate rejected: " + err.Error())
	}
	inter, _ := certutil.ParseChainPEM(s.cfg.CAChainPEM) // Root+Intermediate
	chain := certutil.ValidateCertificateChain(cert, inter, s.cfg.RootCAPEM, time.Now())
	if chain.Error != nil || !chain.TrustedChain {
		return store.Certificate{}, errors.New("certificate does not chain to the configured Root CA")
	}
	csr, _, err := enrollment.ParseAndValidateCSR(e.CSRPEM)
	if err != nil {
		return store.Certificate{}, errors.New("stored CSR no longer parses")
	}
	csrPub, _ := csr.PublicKey.(*mldsa.PublicKey)
	certPub, _ := cert.PublicKey.(*mldsa.PublicKey)
	if csrPub == nil || certPub == nil || !csrPub.Equal(certPub) {
		return store.Certificate{}, errors.New("certificate public key does not match the enrolled CSR")
	}
	stored, _ := s.st.CreateCertificate(store.Certificate{
		EnrollmentID: e.ID, DeviceID: e.DeviceID, AccountID: e.AccountID,
		Serial: info.SerialNumber, Fingerprint: info.FingerprintSHA256, PEM: leafPEM,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Status: store.CertActive,
	})
	_ = s.st.SetEnrollmentStatus(e.ID, store.EnrollmentIssued)
	s.st.Append(store.AuditEvent{Type: "certificate.issue", AccountID: e.AccountID, DeviceID: e.DeviceID, Result: "ok", Detail: stored.Serial})
	return stored, nil
}

func (s *Server) hRevoke(w http.ResponseWriter, r *http.Request) {
	var in struct{ Reason string }
	_ = decode(r, &in)
	id := r.PathValue("id")
	if err := s.st.RevokeCertificate(id, in.Reason); err != nil {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	cert, _ := s.st.Certificate(id)
	s.st.Append(store.AuditEvent{Type: "certificate.revoke", AccountID: cert.AccountID, DeviceID: cert.DeviceID, Result: "ok", Detail: cert.Serial + " " + in.Reason})
	writeJSON(w, http.StatusOK, map[string]string{"certificate_id": id, "status": store.CertRevoked})
}

func (s *Server) hImportCRL(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r, 256<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	if err := parseCRLBytes(body); err != nil {
		writeErr(w, http.StatusBadRequest, "not a parseable CRL: "+err.Error())
		return
	}
	s.crl = body
	s.st.Append(store.AuditEvent{Type: "crl.import", Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "crl updated"})
}

func (s *Server) hAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": s.st.AuditEvents(500)})
}

// ---- reservation & submission ----

func (s *Server) hReserve(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	var in struct {
		DeviceID       string `json:"device_id"`
		OriginalSHA512 string `json:"original_sha512"`
		FileName       string `json:"file_name"`
	}
	if err := decode(r, &in); err != nil || in.DeviceID == "" {
		writeErr(w, http.StatusBadRequest, "device_id is required")
		return
	}
	d, err := s.st.Device(in.DeviceID)
	if err != nil || d.AccountID != c.Sub {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	if d.Status != store.DeviceActive {
		writeErr(w, http.StatusForbidden, "device is "+d.Status)
		return
	}
	cert, err := s.st.CertificateByDevice(d.ID)
	if err != nil || cert.Status != store.CertActive {
		writeErr(w, http.StatusForbidden, "device has no active certificate")
		return
	}
	res, _ := s.st.CreateReservation(store.Reservation{
		AccountID: c.Sub, DeviceID: d.ID, OriginalSHA512: in.OriginalSHA512,
		FileName: sanitizeName(in.FileName), ExpiresAt: time.Now().Add(2 * time.Hour),
	})
	s.audit("signature.reserve", c, d.ID, "ok", res.PublicID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"public_id":        res.PublicID,
		"verification_url": s.verifyURL(res.PublicID),
		"expires_at":       fmtTime(res.ExpiresAt),
	})
}

func (s *Server) hSubmitDocument(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	res, err := s.st.Reservation(r.PathValue("public_id"))
	if err != nil || res.AccountID != c.Sub {
		writeErr(w, http.StatusNotFound, "reservation not found")
		return
	}
	if res.Status == store.ReservationAccepted {
		// idempotent: already completed
		if sig, err := s.st.Signature(res.PublicID); err == nil {
			writeJSON(w, http.StatusOK, submissionResult(sig))
			return
		}
	}

	// The signed PDF arrives either as the raw body or, for a large document
	// pushed in chunks, as a completed resumable upload named by ?upload_id=.
	rc, size, sess, err := s.signedInput(r, c.Sub)
	if err != nil {
		if errors.Is(err, errNoUpload) {
			writeErr(w, http.StatusNotFound, "sesi unggah tidak ditemukan")
			return
		}
		if errors.Is(err, errTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "PDF exceeds the upload limit")
			return
		}
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	defer rc.Close()

	key := fmt.Sprintf("documents/%d/%02d/%s/signed.pdf", time.Now().Year(), int(time.Now().Month()), res.PublicID)

	var sig store.Signature
	if size <= s.cfg.MaxVerifyBytes {
		// verified tier: buffer, strict re-verify, store.
		body, rerr := io.ReadAll(rc)
		if rerr != nil {
			writeErr(w, http.StatusBadRequest, "read")
			return
		}
		info, reason := s.strictVerify(res, body)
		if reason != "" {
			s.audit("signature.submit", c, res.DeviceID, "reject", reason)
			writeErr(w, http.StatusUnprocessableEntity, reason)
			return
		}
		if perr := s.st.PutObject(key, body); perr != nil {
			writeErr(w, http.StatusInternalServerError, "store")
			return
		}
		sig, err = s.st.CreateSignature(store.Signature{
			PublicID: res.PublicID, AccountID: res.AccountID, DeviceID: res.DeviceID,
			OriginalSHA512: res.OriginalSHA512, SignedSHA512: hashutil.CalculateSHA512(body),
			StorageObjectKey: key, SignedSize: len(body),
			ServerReceivedAt: time.Now().UTC(), VerificationStatus: store.VerificationAccepted,
			Algorithm: "ML-DSA-65", PDFProfile: "PAdES_B",
			CertSerial: info.CertSerial, CertFingerprint: info.CertFingerprint,
			CertificateID: info.CertificateID, ClientClaimedSigningTime: info.ClaimedTime,
		})
	} else {
		// store-only tier: too large to verify in memory. Stream to storage
		// while hashing; the record keeps the SHA-512 but no certificate
		// linkage, and the public page marks it "tidak diverifikasi server".
		h := sha512.New()
		if perr := s.st.PutObjectFrom(key, io.TeeReader(rc, h), size); perr != nil {
			writeErr(w, http.StatusInternalServerError, "store")
			return
		}
		sig, err = s.st.CreateSignature(store.Signature{
			PublicID: res.PublicID, AccountID: res.AccountID, DeviceID: res.DeviceID,
			OriginalSHA512: res.OriginalSHA512, SignedSHA512: hex.EncodeToString(h.Sum(nil)),
			StorageObjectKey: key, SignedSize: int(size),
			ServerReceivedAt: time.Now().UTC(), VerificationStatus: store.VerificationStoredOnly,
			Algorithm: "ML-DSA-65", PDFProfile: "PAdES_B",
		})
	}
	if err != nil {
		writeErr(w, http.StatusConflict, "submission already recorded")
		return
	}

	_ = s.st.SetReservationStatus(res.PublicID, store.ReservationAccepted)
	s.audit("signature.submit", c, res.DeviceID, "accept", res.PublicID+" "+sig.VerificationStatus)
	if sess != nil {
		s.uploads.discard(sess)
	}
	writeJSON(w, http.StatusOK, submissionResult(sig))
}

// signedInput returns a reader + byte count for the submitted PDF, from either
// the raw request body or a completed resumable upload (?upload_id=). When it
// is an upload the returned *uploadSession must be discarded by the caller
// after a successful submit; rc is always the caller's to Close.
func (s *Server) signedInput(r *http.Request, account string) (io.ReadCloser, int64, *uploadSession, error) {
	if id := r.URL.Query().Get("upload_id"); id != "" {
		sess := s.uploads.get(id, account)
		if sess == nil {
			return nil, 0, nil, errNoUpload
		}
		f, err := os.Open(sess.path)
		if err != nil {
			return nil, 0, nil, err
		}
		return f, sess.size, sess, nil
	}
	body, err := readBody(r, s.cfg.MaxUploadBytes)
	if err != nil {
		return nil, 0, nil, err
	}
	if err := withinLimit(body, s.cfg.MaxUploadBytes); err != nil {
		return nil, 0, nil, errTooLarge
	}
	return io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil, nil
}

func submissionResult(sig store.Signature) map[string]any {
	status := "accepted"
	if sig.VerificationStatus == store.VerificationStoredOnly {
		status = "stored_unverified"
	}
	return map[string]any{
		"public_id":           sig.PublicID,
		"status":              status,
		"verification_status": sig.VerificationStatus,
		"signed_pdf_sha512":   sig.SignedSHA512,
		"certificate_serial":  sig.CertSerial,
		"server_received_at":  fmtTime(sig.ServerReceivedAt),
	}
}

func (s *Server) hGetSignature(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil || sig.AccountID != claims(r).Sub {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, sig)
}

func (s *Server) hDownload(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil || sig.AccountID != claims(r).Sub {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	b, err := s.st.GetObject(sig.StorageObjectKey)
	if err != nil {
		writeErr(w, http.StatusNotFound, "object missing")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	_, _ = w.Write(b)
}

func (s *Server) hMySignatures(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"signatures": s.st.SignaturesByAccount(claims(r).Sub)})
}

// ---- public verifier ----

func (s *Server) hPublicVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(s.cfg.MaxUploadBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "expected multipart/form-data with a 'file' field")
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing 'file'")
		return
	}
	defer f.Close()
	pdf, err := readAll(f, s.cfg.MaxUploadBytes)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
		return
	}
	res, err := verification.VerifyPDF(pdf, verification.Options{
		RootPEM: s.cfg.RootCAPEM, IntermediatePEM: s.cfg.CAChainPEM, CRLPEM: s.crl,
		RequireMLDSAOnly: true, Timeout: 15 * time.Second,
	})
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	out := map[string]any{"verification": res, "registered": false}
	if len(res.Signatures) > 0 {
		if pid := res.Signatures[0].PublicID(); pid != "" {
			if sig, err := s.st.Signature(pid); err == nil {
				a, _ := s.st.Account(sig.AccountID)
				d, _ := s.st.Device(sig.DeviceID)
				out["registered"] = true
				out["record"] = s.publicRecord(sig, a, d)
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) hPublicRecord(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such record")
		return
	}
	a, _ := s.st.Account(sig.AccountID)
	d, _ := s.st.Device(sig.DeviceID)
	writeJSON(w, http.StatusOK, s.publicRecord(sig, a, d))
}

// publicRecord is the display-safe record behind the QR page (§16.3). It
// reflects the CURRENT certificate status, so a historic signature stays
// readable with a clear "revoked" marker (§25.6).
func (s *Server) publicRecord(sig store.Signature, a store.Account, d store.Device) map[string]any {
	certStatus := "active"
	note := "QR memastikan kecocokan dengan catatan server; integritas seluruh dokumen diverifikasi dari file PDF asli."
	c, cerr := s.st.CertificateBySerial(sig.CertSerial)
	if sig.VerificationStatus == store.VerificationStoredOnly {
		certStatus = "not_server_verified"
		note = "Berkas ini terlalu besar untuk diverifikasi otomatis di server. " +
			"Server hanya mencatat SHA-512-nya dan menyimpan salinannya. " +
			"Verifikasi tanda tangan secara manual dengan mengunggah PDF di halaman verifikasi."
	} else if cerr == nil && c.Status == store.CertRevoked {
		certStatus = "revoked"
	} else if d.Status == store.DeviceLost {
		certStatus = "device_reported_lost"
	}
	return map[string]any{
		"public_id":                   sig.PublicID,
		"signer_name":                 a.DisplayName,
		"position":                    a.Position,
		"nip":                         a.NIP,
		"device_label":                d.Label,
		"certificate_serial":          sig.CertSerial,
		"certificate_fingerprint":     sig.CertFingerprint,
		"certificate_status":          certStatus,
		"verification_status":         sig.VerificationStatus,
		"signed_pdf_sha512":           sig.SignedSHA512,
		"client_claimed_signing_time": sig.ClientClaimedSigningTime,
		"server_received_at":          fmtTime(sig.ServerReceivedAt),
		"note":                        note,
	}
}

func (s *Server) publicBase() string {
	base := strings.TrimRight(s.cfg.PublicBaseURL, "/")
	if base == "" {
		base = "http://localhost:8443"
	}
	return base
}

func (s *Server) verifyURL(publicID string) string { return s.publicBase() + "/v/" + publicID }

func isLoopbackBase(b string) bool {
	return b == "" || strings.Contains(b, "localhost") || strings.Contains(b, "127.0.0.1")
}

// qrTarget builds what the QR code encodes for one signature.
//
// The signer is already logged into a server at some address; the QR should
// just point there. In order: an explicit ?base= from the client, then the
// address the /stamp request actually came in on (i.e. the client's own
// server URL, from the Host header), then the configured PublicBaseURL. The
// first of those that is NOT loopback wins and the QR becomes
// <that>/v/{id} — one scan on any device on the same network opens the
// result. If every candidate is localhost/127.0.0.1 (e.g. the signer runs on
// the same box as the server) a link would be useless from a phone, so the
// QR carries the bare verification ID as plain text instead.
func (s *Server) qrTarget(r *http.Request, publicID string) string {
	for _, cand := range []string{
		strings.TrimSpace(r.URL.Query().Get("base")),
		reqBase(r),
		strings.TrimRight(s.cfg.PublicBaseURL, "/"),
	} {
		cand = strings.TrimRight(cand, "/")
		if isLoopbackBase(cand) {
			continue
		}
		if !strings.HasPrefix(cand, "http://") && !strings.HasPrefix(cand, "https://") {
			cand = "http://" + cand
		}
		return cand + "/v/" + publicID
	}
	return publicID
}
