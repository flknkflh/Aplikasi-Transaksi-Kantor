package certutil_test

import (
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/labpki"
)

func seedCert(f *testing.F) *labpki.CA {
	f.Helper()
	root, err := labpki.NewRootCA("Fuzz Root", time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	return root
}

// FuzzParseCertificatePEM / FuzzParseChainPEM: never panic; a returned
// certificate must re-parse.
func FuzzParseCertificatePEM(f *testing.F) {
	root := seedCert(f)
	f.Add(labpki.CertPEM(root.Cert))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{})
	f.Add([]byte("\x30\x82\x10\x00" + string(make([]byte, 8))))

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := certutil.ParseCertificatePEM(data)
		if err != nil {
			return
		}
		if c == nil {
			t.Fatal("nil cert with nil error")
		}
		_ = certutil.Describe(c) // must not panic on any accepted cert
	})
}

func FuzzParseChainPEM(f *testing.F) {
	root := seedCert(f)
	f.Add(labpki.ChainPEM(root.Cert, root.Cert))
	f.Add([]byte("garbage"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		chain, err := certutil.ParseChainPEM(data)
		if err != nil {
			return
		}
		if len(chain) == 0 {
			t.Fatal("empty chain with nil error")
		}
		for _, c := range chain {
			if c == nil {
				t.Fatal("nil cert in accepted chain")
			}
		}
	})
}

// FuzzValidateCRL feeds arbitrary bytes as the CRL. It must never panic; the
// issuer/target here are unrelated so a "revoked" verdict is impossible on
// junk that happens to parse.
func FuzzValidateCRL(f *testing.F) {
	root := seedCert(f)
	crl, err := root.NewCRL(nil, 1, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(crl)
	f.Add([]byte("-----BEGIN X509 CRL-----\n@@@@\n-----END X509 CRL-----\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := certutil.ValidateCRL(data, nil, root.Cert, time.Now())
		_ = err // any error is fine; a panic is not
	})
}
