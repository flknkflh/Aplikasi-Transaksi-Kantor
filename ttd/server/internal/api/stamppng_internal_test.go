package api

import (
	"os"
	"testing"
)

// TestDumpCaptionSample renders one full caption+QR stamp to a PNG so the
// layout can be eyeballed. It is skipped unless PQC_DUMP_STAMP points at an
// output path, e.g.:
//
//	PQC_DUMP_STAMP=/tmp/stamp.png go test ./internal/api/ -run TestDumpCaptionSample -count=1
func TestDumpCaptionSample(t *testing.T) {
	out := os.Getenv("PQC_DUMP_STAMP")
	if out == "" {
		t.Skip("set PQC_DUMP_STAMP=<path.png> to render a sample stamp")
	}
	png, err := buildStampPNG("https://verify.example/v/sig_demo1234", captionData{
		FullName:    "Gita Aurora, S.Ap., M.P.A.",
		Position:    "Plt. Asisten Deputi Perumusan dan Koordinasi Kebijakan Penerapan Akuntabilitas Aparatur dan Pengawasan",
		NIP:         "198704012011012005",
		IssuedPlace: "Jakarta",
		DateText:    idDate(jakartaNow()),
	}, 1400)
	if err != nil {
		t.Fatalf("buildStampPNG: %v", err)
	}
	if err := os.WriteFile(out, png, 0o644); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
	t.Logf("wrote %d bytes to %s", len(png), out)
}
