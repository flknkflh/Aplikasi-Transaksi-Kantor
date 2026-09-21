package signing

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/images"
	qrcode "github.com/skip2/go-qrcode"
)

// appearanceSize is the signature widget size in PDF points (~113x42 mm).
const (
	appearanceW = 320.0
	appearanceH = 120.0
	qrSide      = 96.0
)

// BuildSignatureAppearance renders the visible signature block: signer
// identity, claimed signing time, certificate serial, the public transaction
// id, and a QR code linking to the verification page (Rencana V1 §2, §15.2,
// §16.3). The QR content is the verification URL when provided, otherwise the
// public id itself.
func BuildSignatureAppearance(leaf *x509.Certificate, o Options) (*pdfsign.Appearance, error) {
	app := pdfsign.NewAppearance(appearanceW, appearanceH).
		Background(255, 255, 255).
		Border(0.75, 90, 90, 90)

	name := o.SignerName
	if name == "" {
		name = leaf.Subject.CommonName
	}
	serial := fmt.Sprintf("%x", leaf.SerialNumber)
	claimed := o.ClaimedSigningTime
	if claimed.IsZero() {
		claimed = time.Now()
	}

	lines := []string{
		"Ditandatangani secara digital oleh:",
		safeText(name),
		"Algoritma: ML-DSA-65",
		"No. sertifikat: " + shorten(serial, 32),
		"Waktu (klaim klien): " + claimed.Format("2006-01-02 15:04:05 -07:00"),
	}
	if o.Reason != "" {
		lines = append(lines, "Alasan: "+safeText(o.Reason))
	}
	if o.PublicID != "" {
		lines = append(lines, "ID verifikasi: "+o.PublicID)
	}

	helv := pdfsign.StandardFont(pdfsign.Helvetica)
	helvBold := pdfsign.StandardFont(pdfsign.HelveticaBold)
	y := appearanceH - 14
	for i, ln := range lines {
		size := 7.0
		font := helv
		if i == 1 { // signer name
			size = 10.0
			font = helvBold
		}
		app.Text(ln).Font(font, size).Position(6, y)
		y -= size + 3
	}

	if o.IncludeQR {
		content := o.VerificationURL
		if content == "" {
			content = o.PublicID
		}
		if content != "" {
			png, err := qrcode.Encode(content, qrcode.Medium, 256)
			if err != nil {
				return nil, fmt.Errorf("signing: encode QR: %w", err)
			}
			img := &images.Image{Name: "qr-" + o.PublicID, Data: png}
			app.Image(img).
				Rect(appearanceW-qrSide-6, (appearanceH-qrSide)/2, qrSide, qrSide).
				ScaleFit()
		}
	}
	return app, nil
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// safeText keeps appearance strings on one line.
func safeText(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}
