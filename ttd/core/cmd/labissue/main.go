// Command labissue is a TEST-ONLY helper: it reads a device CSR (PEM) on
// stdin, builds a throwaway lab Root + Intermediate CA, issues a device
// certificate for that CSR, and prints {root_pem, chain_pem} as JSON.
//
// It exists so the WebAssembly bridge can be exercised end to end from Node
// (web/test) without standing up the whole server. The CA it creates lives
// only for this one process and its private keys are never written anywhere.
// Never use this for anything but tests.
package main

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/labpki"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "labissue:", err)
		os.Exit(1)
	}
}

func run() error {
	csrPEM, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	csr, _, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		return fmt.Errorf("csr: %w", err)
	}
	root, err := labpki.NewRootCA("Lab Root (test only)", 24*time.Hour)
	if err != nil {
		return err
	}
	inter, err := labpki.NewIntermediateCA(root, "Lab Intermediate (test only)", 24*time.Hour)
	if err != nil {
		return err
	}
	leaf, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: "Lab Device"}, Validity: 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"root_pem":  string(labpki.CertPEM(root.Cert)),
		"chain_pem": string(labpki.ChainPEM(leaf, inter.Cert)),
	})
}
