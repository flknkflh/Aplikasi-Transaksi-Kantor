// Package spike runs the M1 cross-platform proof from Rencana V1 §10.1 / §32
// in a single call: build a lab ML-DSA-65 PKI, enroll a device, sign a PDF,
// verify it against the explicit Root CA, and prove that a tampered PDF and a
// wrong Root CA are both rejected. It records timing, memory, and signature
// size so the same routine can be run from the Windows CLI and from Android.
package spike

import (
	"crypto/x509/pkix"
	"fmt"
	"runtime"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/verification"
)

// Config is the spike input.
type Config struct {
	InputPDF    []byte
	SignerName  string // e.g. "Windows Laptop" or the operator's name
	DeviceLabel string
	Platform    string // "windows" | "android"
	PublicID    string // simulated reservation id
}

// Check is one pass/fail assertion.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Artifacts holds the PEM/DER material produced by the run so a caller (the
// CLI) can write it to disk. None of it is secret except DeviceKeyPKCS8PEM.
type Artifacts struct {
	RootCertPEM         []byte `json:"-"`
	IntermediateCertPEM []byte `json:"-"`
	ChainPEM            []byte `json:"-"` // leaf + intermediate
	DeviceCertPEM       []byte `json:"-"`
	DeviceKeyPKCS8PEM   []byte `json:"-"` // SECRET — lab only
	CRLPEM              []byte `json:"-"`
	CSRPEM              []byte `json:"-"`
	SignedPDF           []byte `json:"-"`
	WrongRootPEM        []byte `json:"-"`
}

// Report is the spike result (Rencana V1 §32 "laporan").
type Report struct {
	Algorithm          string  `json:"algorithm"`
	PDFProfile         string  `json:"pdf_profile"`
	Platform           string  `json:"platform"`
	GoVersion          string  `json:"go_version"`
	OSArch             string  `json:"os_arch"`
	InputPDFBytes      int     `json:"input_pdf_bytes"`
	SignedPDFBytes     int     `json:"signed_pdf_bytes"`
	SignatureOverhead  int     `json:"signature_overhead_bytes"`
	KeygenMillis       int64   `json:"keygen_millis"`
	SignMillis         int64   `json:"sign_millis"`
	VerifyMillis       int64   `json:"verify_millis"`
	PeakHeapAllocBytes uint64  `json:"peak_heap_alloc_bytes"`
	OriginalSHA512     string  `json:"original_sha512"`
	SignedSHA512       string  `json:"signed_pdf_sha512"`
	CertificateSerial  string  `json:"certificate_serial"`
	Checks             []Check `json:"checks"`
	Passed             bool    `json:"passed"`

	Artifacts Artifacts `json:"-"`
}

func (r *Report) add(name string, passed bool, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: passed, Detail: fmt.Sprintf(format, args...)})
	if !passed {
		r.Passed = false
	}
}

// Run executes the spike. It returns a Report even on assertion failures; a
// non-nil error means the run could not be carried out at all.
func Run(cfg Config) (*Report, error) {
	if len(cfg.InputPDF) == 0 {
		return nil, fmt.Errorf("spike: InputPDF is empty")
	}
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}
	if cfg.SignerName == "" {
		cfg.SignerName = "Spike Operator"
	}
	if cfg.PublicID == "" {
		cfg.PublicID = "sig_spike_" + time.Now().UTC().Format("20060102T150405Z")
	}

	r := &Report{
		Algorithm:     keys.Algorithm,
		PDFProfile:    "PAdES_B",
		Platform:      cfg.Platform,
		GoVersion:     runtime.Version(),
		OSArch:        runtime.GOOS + "/" + runtime.GOARCH,
		InputPDFBytes: len(cfg.InputPDF),
		Passed:        true,
	}

	// --- lab PKI: Root -> Intermediate ---
	root, err := labpki.NewRootCA("PQC PDF Root CA (LAB)", 10*365*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("spike: root CA: %w", err)
	}
	inter, err := labpki.NewIntermediateCA(root, "PQC Device Signing CA (LAB)", 5*365*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("spike: intermediate CA: %w", err)
	}

	// --- device key + CSR (client side) ---
	t0 := time.Now()
	deviceKey, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return nil, fmt.Errorf("spike: device key: %w", err)
	}
	r.KeygenMillis = time.Since(t0).Milliseconds()

	deviceKeyPEM, err := keys.MarshalPKCS8PEM(deviceKey)
	if err != nil {
		return nil, err
	}
	csrPEM, err := enrollment.CreateDeviceCSR(deviceKeyPEM, enrollment.Request{
		CommonName:   cfg.SignerName,
		Organization: "PQC PDF Sign Lab",
		DeviceLabel:  cfg.DeviceLabel,
		Platform:     cfg.Platform,
	})
	if err != nil {
		return nil, fmt.Errorf("spike: CSR: %w", err)
	}
	csr, csrInfo, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("spike: validate CSR: %w", err)
	}
	r.add("csr_proof_of_possession", csrInfo.ProofOfPossession, "CSR self-signature verified, key %s", csrInfo.PublicKeyAlgorithm)

	// --- CA issues the device certificate (identity assigned by CA, not CSR) ---
	deviceCert, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{
			CommonName:   cfg.SignerName,
			Organization: []string{"PQC PDF Sign Lab"},
		},
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("spike: issue device cert: %w", err)
	}
	r.CertificateSerial = fmt.Sprintf("%x", deviceCert.SerialNumber)
	r.add("cert_matches_device_key", keys.SameKeyPair(deviceKey, deviceCert.PublicKey),
		"issued certificate public key equals on-device key")

	chainPEM := labpki.ChainPEM(deviceCert, inter.Cert)
	rootPEM := labpki.CertPEM(root.Cert)
	crlPEM, err := inter.NewCRL(nil, 1, 7*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("spike: CRL: %w", err)
	}

	// wrong root: a second, unrelated root CA
	wrongRoot, err := labpki.NewRootCA("Unrelated Root CA (LAB)", 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	wrongRootPEM := labpki.CertPEM(wrongRoot.Cert)

	// --- sign ---
	t0 = time.Now()
	signRes, err := signing.SignPDF(cfg.InputPDF, deviceKeyPEM, chainPEM, signing.Options{
		Reason:             "Spike M1 cross-platform proof",
		Location:           "Lab",
		SignerName:         cfg.SignerName,
		PublicID:           cfg.PublicID,
		VerificationURL:    "https://verify.example.id/v/" + cfg.PublicID,
		IncludeQR:          true,
		ClaimedSigningTime: time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("spike: sign: %w", err)
	}
	r.SignMillis = time.Since(t0).Milliseconds()
	r.SignedPDFBytes = len(signRes.SignedPDF)
	r.SignatureOverhead = len(signRes.SignedPDF) - len(cfg.InputPDF)
	r.OriginalSHA512 = signRes.OriginalSHA512
	r.SignedSHA512 = signRes.SignedSHA512
	r.add("signed_pdf_produced", len(signRes.SignedPDF) > len(cfg.InputPDF),
		"signed PDF is %d bytes (+%d)", r.SignedPDFBytes, r.SignatureOverhead)

	// --- verify: good path ---
	t0 = time.Now()
	good, err := verification.VerifyPDF(signRes.SignedPDF, verification.Options{
		RootPEM:          rootPEM,
		IntermediatePEM:  labpki.CertPEM(inter.Cert),
		CRLPEM:           crlPEM,
		RequireMLDSAOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("spike: verify: %w", err)
	}
	r.VerifyMillis = time.Since(t0).Milliseconds()
	r.add("verify_explicit_root_valid", good.Valid, "verification result valid=%v %s", good.Valid, firstErr(good))
	if len(good.Signatures) > 0 {
		s := good.Signatures[0]
		r.add("signature_algorithm_mldsa65", s.Algorithm == "ML-DSA-65", "algorithm=%s", s.Algorithm)
		r.add("signature_trusted_chain", s.TrustedChain, "trusted_chain=%v", s.TrustedChain)
		r.add("signature_not_revoked", !s.Revoked, "revoked=%v", s.Revoked)
	}

	// --- verify: tampered PDF must fail ---
	tampered := append([]byte(nil), signRes.SignedPDF...)
	flip := len(tampered) / 2
	tampered[flip] ^= 0xFF
	bad, err := verification.VerifyPDF(tampered, verification.Options{
		RootPEM: rootPEM, IntermediatePEM: labpki.CertPEM(inter.Cert), RequireMLDSAOnly: true,
	})
	if err != nil {
		r.add("tampered_pdf_rejected", true, "verification errored out: %v", err)
	} else {
		r.add("tampered_pdf_rejected", !bad.Valid, "tampered verification valid=%v (want false)", bad.Valid)
	}

	// --- verify: wrong Root CA must fail ---
	wrong, err := verification.VerifyPDF(signRes.SignedPDF, verification.Options{
		RootPEM: wrongRootPEM, RequireMLDSAOnly: true,
	})
	if err != nil {
		r.add("wrong_root_rejected", true, "verification errored out: %v", err)
	} else {
		r.add("wrong_root_rejected", !wrong.Valid, "wrong-root verification valid=%v (want false)", wrong.Valid)
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.PeakHeapAllocBytes = ms.HeapAlloc

	r.Artifacts = Artifacts{
		RootCertPEM:         rootPEM,
		IntermediateCertPEM: labpki.CertPEM(inter.Cert),
		ChainPEM:            chainPEM,
		DeviceCertPEM:       labpki.CertPEM(deviceCert),
		DeviceKeyPKCS8PEM:   deviceKeyPEM,
		CRLPEM:              crlPEM,
		CSRPEM:              csrPEM,
		SignedPDF:           signRes.SignedPDF,
		WrongRootPEM:        wrongRootPEM,
	}
	return r, nil
}

func firstErr(r *verification.Result) string {
	if len(r.Errors) > 0 {
		return "errors=" + r.Errors[0]
	}
	if len(r.Signatures) > 0 && len(r.Signatures[0].Errors) > 0 {
		return "sig_errors=" + r.Signatures[0].Errors[0]
	}
	return ""
}
