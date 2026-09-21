package api

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"path"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/verification"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// verifiedInfo carries the facts a passing submission established, so the
// caller can persist them without re-reading global state.
type verifiedInfo struct {
	CertificateID   string
	CertSerial      string
	CertFingerprint string
	ClaimedTime     string
}

// strictVerify runs the submission checks from Rencana V1 §15.3. It returns a
// non-empty reason string on rejection.
func (s *Server) strictVerify(res store.Reservation, pdf []byte) (verifiedInfo, string) {
	if len(pdf) < 5 || string(pdf[:5]) != "%PDF-" {
		return verifiedInfo{}, "not a PDF (missing %PDF- magic)"
	}
	// One reservation, one document.
	if _, err := s.st.Signature(res.PublicID); err == nil {
		return verifiedInfo{}, "this reservation has already been completed"
	}
	d, err := s.st.Device(res.DeviceID)
	if err != nil || d.Status != store.DeviceActive {
		return verifiedInfo{}, "device is not active"
	}

	vr, err := verification.VerifyPDF(pdf, verification.Options{
		RootPEM:          s.cfg.RootCAPEM,
		IntermediatePEM:  s.cfg.CAChainPEM,
		CRLPEM:           s.crl,
		RequireMLDSAOnly: true,
		Timeout:          15 * time.Second, // bound a malformed-PDF parser loop (§26)
	})
	if err != nil {
		return verifiedInfo{}, "verification error: " + err.Error()
	}
	if len(vr.Signatures) != 1 {
		return verifiedInfo{}, "expected exactly one signature"
	}
	sig := vr.Signatures[0]
	if !vr.Valid || !sig.Valid {
		return verifiedInfo{}, firstReason(vr, "signature is not valid")
	}
	if sig.Algorithm != "ML-DSA-65" {
		return verifiedInfo{}, "signature algorithm is not ML-DSA-65"
	}
	if !sig.TrustedChain {
		return verifiedInfo{}, "certificate chain does not reach the configured Root CA"
	}
	if sig.Revoked {
		return verifiedInfo{}, "signer certificate is revoked"
	}
	if sig.PublicID() != res.PublicID {
		return verifiedInfo{}, "public id in the PDF does not match this reservation"
	}

	cert, err := s.st.CertificateBySerial(sig.CertificateSerial)
	if err != nil {
		return verifiedInfo{}, "signer certificate is not registered with this server"
	}
	if cert.AccountID != res.AccountID {
		return verifiedInfo{}, "signer certificate belongs to a different account"
	}
	if cert.DeviceID != res.DeviceID {
		return verifiedInfo{}, "signer certificate belongs to a different device"
	}
	if cert.Status != store.CertActive {
		return verifiedInfo{}, "signer certificate is " + cert.Status
	}
	if cert.Fingerprint != sig.CertificateFingerprint {
		return verifiedInfo{}, "certificate fingerprint mismatch"
	}

	return verifiedInfo{
		CertificateID:   cert.ID,
		CertSerial:      cert.Serial,
		CertFingerprint: cert.Fingerprint,
		ClaimedTime:     sig.ClientClaimedSigningTime,
	}, ""
}

func firstReason(vr *verification.Result, fallback string) string {
	if len(vr.Errors) > 0 {
		return vr.Errors[0]
	}
	if len(vr.Signatures) > 0 && len(vr.Signatures[0].Errors) > 0 {
		return vr.Signatures[0].Errors[0]
	}
	return fallback
}

func parseCRLBytes(b []byte) error {
	der := b
	if blk, _ := pem.Decode(b); blk != nil {
		der = blk.Bytes
	}
	_, err := x509.ParseRevocationList(der)
	return err
}

func sanitizeName(name string) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_' || r == ' ':
			return r
		default:
			return '_'
		}
	}, name)
	if name == "" || name == "." || name == ".." {
		return "document.pdf"
	}
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

func readAll(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errTooLarge
	}
	return b, nil
}
