package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// LabIssuer wires the server to the offline ca-admin binary so certificate
// issuance, revocation, and CRL publication can happen without a human in the
// loop. In the RB-1 model this is the normal path: an admin's one-click
// account approval is the only manual gate, and the device certificate is
// then issued automatically on first enrolment (see tryAutoIssue). A truly
// air-gapped deployment leaves Config.LabIssuer nil and an admin runs
// ca-admin by hand (docs/pki-ceremony.md).
type LabIssuer struct {
	Bin        string // path to the ca-admin executable
	Dir        string // CA directory (root/ intermediate/ public/)
	Passphrase string // PQC_CA_PASSPHRASE for ca-admin (may be empty in a lab)
	Operator   string // PQC_CA_OPERATOR label recorded in ceremony.jsonl
	Org        string // default certificate organization when the account has none
}

func (li *LabIssuer) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, li.Bin, args...)
	cmd.Env = append(os.Environ(),
		"PQC_CA_PASSPHRASE="+li.Passphrase,
		"PQC_CA_OPERATOR="+firstNonEmpty(li.Operator, "pqc-api"))
	return cmd.CombinedOutput()
}

// issueViaCA runs `ca-admin issue` for an enrollment and returns the leaf
// certificate PEM. Identity is taken from the verified account, never the CSR.
func (s *Server) issueViaCA(ctx context.Context, e store.Enrollment) ([]byte, error) {
	li := s.cfg.LabIssuer
	if li == nil {
		return nil, fmt.Errorf("no CA issuer configured")
	}
	acc, _ := s.st.Account(e.AccountID)
	dev, _ := s.st.Device(e.DeviceID)
	cn := firstNonEmpty(acc.FullName, acc.DisplayName, acc.Email, "Lab Device")
	org := firstNonEmpty(acc.Organization, li.Org, "PQC PDF Sign (lab)")

	tmp, err := os.MkdirTemp("", "pqc-issue-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	csrPath := filepath.Join(tmp, "device.csr.pem")
	outPath := filepath.Join(tmp, "device.crt.pem")
	if err := os.WriteFile(csrPath, e.CSRPEM, 0o600); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := li.run(ctx, "issue",
		"--dir", li.Dir, "--csr", csrPath,
		"--account", firstNonEmpty(acc.Email, e.AccountID),
		"--device", firstNonEmpty(dev.Label, e.DeviceID),
		"--cn", cn, "--org", org, "--out", outPath); err != nil {
		return nil, fmt.Errorf("ca-admin issue: %s", clip(out, 400))
	}
	return os.ReadFile(outPath)
}

// revokeViaCA records a serial as revoked in the CA ledger. An
// already-revoked serial is not an error.
func (s *Server) revokeViaCA(ctx context.Context, serialHex, reason string) error {
	li := s.cfg.LabIssuer
	if li == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := li.run(ctx, "revoke", "--dir", li.Dir, "--serial", serialHex, "--reason", reason)
	if err != nil && !clipContains(out, "already revoked") {
		return fmt.Errorf("ca-admin revoke: %s", clip(out, 400))
	}
	return nil
}

// publishCRLViaCA asks the CA to publish a fresh CRL and returns its PEM so
// the caller can swap it into s.crl.
func (s *Server) publishCRLViaCA(ctx context.Context) ([]byte, error) {
	li := s.cfg.LabIssuer
	if li == nil {
		return nil, nil
	}
	tmp, err := os.MkdirTemp("", "pqc-crl-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	outPath := filepath.Join(tmp, "crl.pem")
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if out, err := li.run(ctx, "crl", "--dir", li.Dir, "--out", outPath); err != nil {
		return nil, fmt.Errorf("ca-admin crl: %s", clip(out, 400))
	}
	return os.ReadFile(outPath)
}

// hLabIssue is the manual "issue straight from an enrollment" admin endpoint
// (kept for retries / air-gapped operators who still want one button).
func (s *Server) hLabIssue(w http.ResponseWriter, r *http.Request) {
	if s.cfg.LabIssuer == nil {
		writeErr(w, http.StatusNotFound, "lab issuer not enabled")
		return
	}
	e, err := s.st.Enrollment(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "enrollment not found")
		return
	}
	leaf, err := s.issueViaCA(r.Context(), e)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "issuance failed: "+err.Error())
		return
	}
	stored, err := s.bindIssuedCert(e, leaf)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"certificate_id": stored.ID, "serial": stored.Serial, "fingerprint": stored.Fingerprint,
	})
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func clip(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

func clipContains(b []byte, sub string) bool {
	return len(b) > 0 && strings.Contains(string(b), sub)
}
