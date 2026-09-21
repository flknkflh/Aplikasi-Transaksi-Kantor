// Command ca-admin runs the offline CA operator workflow for PQC PDF Sign V1
// (Rencana V1 §13, §14, §17.5): validate device CSRs, issue device
// certificates whose identity is assigned by the operator (never taken from
// the CSR subject), record revocations, and publish CRLs.
//
// With PQC_CA_PASSPHRASE set the Root and Intermediate private keys are
// stored encrypted (Argon2id + AES-256-GCM) and every state-changing command
// appends a checksummed line to ceremony.jsonl. Without it the keys are
// plaintext — lab only. The full production runbook is docs/pki-ceremony.md.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/labpki"
)

func pkixName(cn, org string) pkix.Name {
	n := pkix.Name{CommonName: cn}
	if org != "" {
		n.Organization = []string{org}
	}
	return n
}

// reasonCodes maps the CLI --reason string to an RFC 5280 code.
var reasonCodes = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"cACompromise":         2,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
	"certificateHold":      6,
	"privilegeWithdrawn":   9,
}

func open(dir string) (Store, error) {
	return openStore(dir, os.Getenv("PQC_CA_PASSPHRASE"), os.Getenv("PQC_CA_OPERATOR"))
}

const usage = `ca-admin — offline CA operator for PQC PDF Sign V1

usage: ca-admin <command> [flags]

  init         create a Root + Intermediate ML-DSA-65 CA under --dir
  validate     check a device CSR (proof of possession, ML-DSA-65)
  issue        issue one device certificate (identity assigned via flags)
  batch-issue  issue certificates for every CSR in a directory
  revoke       record a serial as revoked (--reason keyCompromise|superseded|...)
  crl          publish a fresh CRL signed by the Intermediate CA
  status       CA fingerprints, counts, and the "no private key in public/" gate
  backup       write a .tar.gz of the whole CA directory
  restore      unpack a ca-admin backup into a new --dir
  show         inspect a certificate or CRL PEM file

Environment:
  PQC_CA_PASSPHRASE   if set, CA keys are stored encrypted (production)
  PQC_CA_OPERATOR     recorded in ceremony.jsonl

Run "ca-admin <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "batch-issue":
		err = cmdBatchIssue(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "crl":
		err = cmdCRL(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "restore":
		err = cmdRestore(os.Args[2:])
	case "show":
		err = cmdShow(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory to create")
	rootCN := fs.String("root-cn", "PQC PDF Root CA", "Root CA common name")
	interCN := fs.String("inter-cn", "PQC Device Signing CA", "Intermediate CA common name")
	_ = fs.Parse(args)

	s := Store{Dir: *dir, Passphrase: os.Getenv("PQC_CA_PASSPHRASE"), Operator: os.Getenv("PQC_CA_OPERATOR")}
	if err := s.Init(*rootCN, *interCN); err != nil {
		return err
	}
	root, _ := s.Root()
	inter, _ := s.Intermediate()

	keyFiles := []string{"root/key.pem", "intermediate/key.pem"}
	if s.encrypted() {
		keyFiles = []string{"root/key.pem.enc", "intermediate/key.pem.enc"}
	}
	_ = s.logCeremony("ca.init", "root+intermediate generated",
		append(keyFiles, "root/cert.pem", "intermediate/cert.pem",
			"public/root-ca.crt.pem", "public/intermediate-ca.crt.pem", "public/ca-chain.pem")...)

	fmt.Printf("CA initialised in %s/\n", *dir)
	fmt.Printf("  root         : %s\n    fp %s\n", root.Cert.Subject, certutil.FingerprintSHA256(root.Cert))
	fmt.Printf("  intermediate : %s\n    fp %s\n", inter.Cert.Subject, certutil.FingerprintSHA256(inter.Cert))
	if s.encrypted() {
		fmt.Println("  CA keys      : ENCRYPTED (Argon2id + AES-256-GCM)")
	} else {
		fmt.Println("  CA keys      : PLAINTEXT — lab only. Set PQC_CA_PASSPHRASE for production.")
	}
	fmt.Printf("  published    : %s/public/{root-ca.crt.pem,intermediate-ca.crt.pem,ca-chain.pem}\n", *dir)
	fmt.Println("  ceremony log : " + s.path("ceremony.jsonl"))
	return nil
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	csrPath := fs.String("csr", "", "device CSR PEM (required)")
	_ = fs.Parse(args)
	if *csrPath == "" {
		return errors.New("-csr is required")
	}
	raw, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	_, info, err := enrollment.ParseAndValidateCSR(raw)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(out))
	fmt.Println("NOTE: the CSR subject above is advisory; identity is assigned at `issue` time.")
	return nil
}

func issueOne(s Store, inter *labpki.CA, csrPEM []byte, account, device, cn, org, crlURL string, days int, outPath string) (IssuedRecord, error) {
	csr, csrInfo, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		return IssuedRecord{}, fmt.Errorf("CSR rejected: %w", err)
	}
	cert, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject:  pkixName(cn, org),
		Validity: time.Duration(days) * 24 * time.Hour,
		CRLURL:   crlURL,
	})
	if err != nil {
		return IssuedRecord{}, err
	}
	if err := os.WriteFile(outPath, labpki.CertPEM(cert), 0o644); err != nil {
		return IssuedRecord{}, err
	}
	if err := os.WriteFile(outPath+".fullchain.pem", labpki.ChainPEM(cert, inter.Cert), 0o644); err != nil {
		return IssuedRecord{}, err
	}
	rec := IssuedRecord{
		Serial: certSerialHex(cert), Subject: cert.Subject.String(), Account: account, DeviceLabel: device,
		Fingerprint: certutil.FingerprintSHA256(cert), NotAfter: cert.NotAfter, IssuedAt: time.Now().UTC(),
		CSRFP: csrInfo.PublicKeyFP,
	}
	return rec, s.appendIssued(rec)
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	csrPath := fs.String("csr", "", "device CSR PEM (required)")
	account := fs.String("account", "", "verified account id (required)")
	device := fs.String("device", "", "device label (required)")
	cn := fs.String("cn", "", "certificate common name to ASSIGN (required)")
	org := fs.String("org", "PQC PDF Sign", "certificate organization")
	days := fs.Int("days", 365, "validity in days")
	crlURL := fs.String("crl-url", "", "CRL distribution point URL (optional)")
	out := fs.String("out", "device.crt.pem", "output certificate PEM")
	_ = fs.Parse(args)
	if *csrPath == "" || *account == "" || *device == "" || *cn == "" {
		return errors.New("-csr, -account, -device and -cn are required")
	}
	s, err := open(*dir)
	if err != nil {
		return err
	}
	inter, err := s.Intermediate()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	rec, err := issueOne(s, inter, raw, *account, *device, *cn, *org, *crlURL, *days, *out)
	if err != nil {
		return err
	}
	_ = s.logCeremony("cert.issue", "1 certificate", "issued.jsonl")
	fmt.Printf("issued %s\n  serial      : %s\n  subject     : %s\n  account     : %s\n  device      : %s\n  fingerprint : %s\n  not_after   : %s\n",
		*out, rec.Serial, rec.Subject, rec.Account, rec.DeviceLabel, rec.Fingerprint, rec.NotAfter.Format(time.RFC3339))
	return nil
}

// cmdBatchIssue issues a certificate for every *.csr.pem in --in. Optional
// per-CSR metadata in <name>.meta.json ({account,device,cn}); otherwise the
// CSR filename stem is used as cn/device and --account for account.
func cmdBatchIssue(args []string) error {
	fs := flag.NewFlagSet("batch-issue", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	in := fs.String("in", "", "directory of *.csr.pem files (required)")
	outDir := fs.String("out", "issued", "output directory for certificates")
	account := fs.String("account", "batch", "default account id")
	org := fs.String("org", "PQC PDF Sign", "certificate organization")
	days := fs.Int("days", 365, "validity in days")
	crlURL := fs.String("crl-url", "", "CRL distribution point URL")
	_ = fs.Parse(args)
	if *in == "" {
		return errors.New("-in is required")
	}
	s, err := open(*dir)
	if err != nil {
		return err
	}
	inter, err := s.Intermediate()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(*in)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}

	type meta struct{ Account, Device, CN string }
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".csr.pem") {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), ".csr.pem")
		m := meta{Account: *account, Device: stem, CN: stem}
		if mb, err := os.ReadFile(filepath.Join(*in, stem+".meta.json")); err == nil {
			_ = json.Unmarshal(mb, &m)
		}
		raw, err := os.ReadFile(filepath.Join(*in, e.Name()))
		if err != nil {
			return err
		}
		rec, err := issueOne(s, inter, raw, m.Account, m.Device, m.CN, *org, *crlURL, *days,
			filepath.Join(*outDir, certFileName(stem)))
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		fmt.Printf("  %s -> %s (%s)\n", e.Name(), rec.Serial, m.CN)
		count++
	}
	_ = s.logCeremony("cert.batch-issue", fmt.Sprintf("%d certificates from %s", count, *in), "issued.jsonl")
	fmt.Printf("batch-issue: %d certificate(s) written to %s/\n", count, *outDir)
	return nil
}

func certFileName(stem string) string { return stem + ".crt.pem" }

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	serial := fs.String("serial", "", "certificate serial in hex (required)")
	reason := fs.String("reason", "unspecified", "keyCompromise|cACompromise|superseded|cessationOfOperation|privilegeWithdrawn|affiliationChanged|certificateHold|unspecified")
	_ = fs.Parse(args)
	if *serial == "" {
		return errors.New("-serial is required (hex, as printed by `issue` or `show`)")
	}
	if _, ok := new(big.Int).SetString(*serial, 16); !ok {
		return fmt.Errorf("invalid hex serial %q", *serial)
	}
	code, ok := reasonCodes[*reason]
	if !ok {
		return fmt.Errorf("unknown reason %q", *reason)
	}
	s, err := open(*dir)
	if err != nil {
		return err
	}
	l, err := s.loadLedger()
	if err != nil {
		return err
	}
	for _, r := range l.Revocations {
		if r.Serial == *serial {
			return fmt.Errorf("serial %s is already revoked (%s)", *serial, r.RevokedAt.Format(time.RFC3339))
		}
	}
	l.Revocations = append(l.Revocations, Revocation{
		Serial: *serial, Reason: *reason, ReasonCode: code, RevokedAt: time.Now().UTC(),
	})
	if err := s.saveLedger(l); err != nil {
		return err
	}
	_ = s.logCeremony("cert.revoke", *serial+" "+*reason, "ledger.json")
	fmt.Printf("recorded revocation of %s (%s / code %d). Run `ca-admin crl` to publish.\n", *serial, *reason, code)
	return nil
}

func cmdCRL(args []string) error {
	fs := flag.NewFlagSet("crl", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	days := fs.Int("days", 7, "CRL validity in days (nextUpdate)")
	out := fs.String("out", "", "also write the CRL here (optional)")
	_ = fs.Parse(args)

	s, err := open(*dir)
	if err != nil {
		return err
	}
	l, err := s.loadLedger()
	if err != nil {
		return err
	}
	inter, err := s.Intermediate()
	if err != nil {
		return err
	}
	rl := make([]labpki.RevokedEntry, 0, len(l.Revocations))
	for _, r := range l.Revocations {
		n, _ := new(big.Int).SetString(r.Serial, 16)
		rl = append(rl, labpki.RevokedEntry{Serial: n, Reason: r.ReasonCode, At: r.RevokedAt})
	}
	l.CRLNumber++
	crlPEM, err := inter.NewCRLDetailed(rl, l.CRLNumber, time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := s.publish(inter, crlPEM); err != nil {
		return err
	}
	if err := s.saveLedger(l); err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, crlPEM, 0o644); err != nil {
			return err
		}
	}
	_ = s.logCeremony("crl.publish", fmt.Sprintf("CRL #%d, %d entries", l.CRLNumber, len(rl)),
		"public/crl.pem", "ledger.json")
	fmt.Printf("published CRL #%d with %d revoked serial(s) -> %s/public/crl.pem\n",
		l.CRLNumber, len(rl), *dir)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	_ = fs.Parse(args)

	s, err := open(*dir)
	if err != nil {
		return err
	}
	root, err := s.Root()
	if err != nil {
		return err
	}
	inter, err := s.Intermediate()
	if err != nil {
		return err
	}
	l, _ := s.loadLedger()
	issued := 0
	if b, err := os.ReadFile(s.path("issued.jsonl")); err == nil {
		issued = strings.Count(strings.TrimSpace(string(b)), "\n") + 1
		if len(b) == 0 {
			issued = 0
		}
	}
	fmt.Printf("CA directory : %s\n", *dir)
	fmt.Printf("keys         : %s\n", map[bool]string{true: "ENCRYPTED", false: "plaintext (lab)"}[s.encrypted()])
	fmt.Printf("root         : %s\n  fp %s  not_after %s\n", root.Cert.Subject, certutil.FingerprintSHA256(root.Cert), root.Cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("intermediate : %s\n  fp %s  not_after %s\n", inter.Cert.Subject, certutil.FingerprintSHA256(inter.Cert), inter.Cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("issued certs : %d\n", issued)
	if l != nil {
		fmt.Printf("revocations  : %d (CRL #%d)\n", len(l.Revocations), l.CRLNumber)
	}
	if name, leak := s.hasPrivateKeyLeak(); leak {
		return fmt.Errorf("GATE FAIL: %s/public/%s contains private key material", *dir, name)
	}
	fmt.Println("gate         : OK — public/ contains no private key material (§23 M7)")
	return nil
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	in := fs.String("in", "", "certificate or CRL PEM file (required)")
	_ = fs.Parse(args)
	if *in == "" {
		return errors.New("-in is required")
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("no PEM block found")
	}
	switch block.Type {
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(certutil.Describe(c), "", "  ")
		fmt.Println(string(out))
	case "X509 CRL":
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return err
		}
		fmt.Printf("CRL issuer      : %s\n", crl.Issuer)
		fmt.Printf("number          : %s\n", crl.Number)
		fmt.Printf("this/next update: %s .. %s\n", crl.ThisUpdate.Format(time.RFC3339), crl.NextUpdate.Format(time.RFC3339))
		fmt.Printf("signature alg   : %s\n", crl.SignatureAlgorithm)
		fmt.Printf("revoked entries : %d\n", len(crl.RevokedCertificateEntries))
		for _, e := range crl.RevokedCertificateEntries {
			fmt.Printf("  - %x  at %s  reason %d\n", e.SerialNumber, e.RevocationTime.Format(time.RFC3339), e.ReasonCode)
		}
	default:
		return fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	return nil
}
