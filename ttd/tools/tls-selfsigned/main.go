// Command tls-selfsigned writes a self-signed ECDSA P-256 TLS server
// certificate + key for local/demo use — the deploy/office stack's own
// entrypoint runs this on first boot so `docker compose up` gets a working
// HTTPS listener with no manual PKI step, matching the "pure Go, no cgo"
// approach the rest of this repo's Docker images already use (no openssl
// binary needed in the runtime image).
//
// This is NOT the certificate the app itself issues to signers (that is a
// separate hierarchy, ttd/core/labpki) — this is only the transport-layer
// (TLS) certificate the server presents to a browser. A self-signed cert
// means the browser shows a trust warning on first visit; swap it for a
// real certificate (an internal CA, or Let's Encrypt if the server has a
// public hostname) for anything beyond local/demo use — see deploy/office/TLS.md.
//
//	tls-selfsigned -out-cert cert.pem -out-key key.pem -host localhost,127.0.0.1[,more,...] [-days 397]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	outCert := flag.String("out-cert", "cert.pem", "output path for the certificate PEM")
	outKey := flag.String("out-key", "key.pem", "output path for the private key PEM")
	hosts := flag.String("host", "localhost,127.0.0.1", "comma-separated DNS names / IP addresses for the certificate's SAN")
	days := flag.Int("days", 397, "validity in days (397 is the longest most browsers still accept for a leaf cert)")
	force := flag.Bool("force", false, "overwrite an existing cert/key instead of leaving them alone")
	flag.Parse()

	if !*force {
		if _, err := os.Stat(*outCert); err == nil {
			if _, err := os.Stat(*outKey); err == nil {
				fmt.Printf("tls-selfsigned: %s and %s already exist, leaving them alone (use -force to regenerate)\n", *outCert, *outKey)
				return
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("tls-selfsigned: generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("tls-selfsigned: serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: firstHost(*hosts), Organization: []string{"Arsip Pusat (self-signed, demo/local only)"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("tls-selfsigned: create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("tls-selfsigned: marshal key: %v", err)
	}

	if err := writePEM(*outCert, "CERTIFICATE", der, 0o644); err != nil {
		log.Fatalf("tls-selfsigned: write cert: %v", err)
	}
	if err := writePEM(*outKey, "PRIVATE KEY", keyDER, 0o600); err != nil {
		log.Fatalf("tls-selfsigned: write key: %v", err)
	}
	fmt.Printf("tls-selfsigned: wrote %s + %s for %s (valid %d days, self-signed — browsers will warn until you replace it)\n",
		*outCert, *outKey, *hosts, *days)
}

func firstHost(hosts string) string {
	if h, _, ok := strings.Cut(hosts, ","); ok {
		return h
	}
	return hosts
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
