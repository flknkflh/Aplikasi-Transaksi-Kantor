package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// QR stamp (Rencana RB-2c, supersedes the appended A4 cover page). The client
// uploads the original PDF right after reserving, together with where the
// signer dropped the QR box in the app (page + fractional rectangle). The
// server draws one "TTD Elektronik" stamp there — signer identity comes from
// the verified account, so it cannot be spoofed — and returns the stamped PDF
// for the client to sign on-device. PDF work stays here, not in core, so the
// Android AAR carries no extra dependency.

// stampPlacement is where the QR goes, as page-relative fractions with the
// origin at the TOP-left (matching how the app's preview canvas reports
// coordinates). X,Y is the top-left corner of the box; W is its width.
type stampPlacement struct {
	Page int
	X, Y float64
	W    float64
}

func (s *Server) hStamp(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	res, err := s.st.Reservation(r.PathValue("public_id"))
	if err != nil || res.AccountID != c.Sub {
		writeErr(w, http.StatusNotFound, "reservation not found")
		return
	}
	if res.Status == store.ReservationAccepted {
		writeErr(w, http.StatusConflict, "this reservation is already completed")
		return
	}
	cert, err := s.st.CertificateByDevice(res.DeviceID)
	if err != nil || cert.Status != store.CertActive {
		writeErr(w, http.StatusConflict, "perangkat belum punya sertifikat aktif")
		return
	}
	acc, err := s.st.Account(c.Sub)
	if err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}

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
	// The server draws the QR with pdfcpu, which parses the whole PDF in
	// memory — refuse the ones too big for that (docs/large-files.md). The
	// client should submit such a document without a server stamp.
	if size > s.cfg.MaxStampBytes {
		_ = rc.Close()
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"berkas %d MB terlalu besar untuk stempel QR di server (maks %d MB). "+
				"Tandatangani tanpa stempel server untuk berkas sebesar ini.",
			size>>20, s.cfg.MaxStampBytes>>20))
		return
	}
	body, err := io.ReadAll(rc)
	_ = rc.Close()
	if sess != nil {
		s.uploads.discard(sess)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		writeErr(w, http.StatusUnprocessableEntity, "bukan berkas PDF")
		return
	}

	places := parseStampPlacements(r)

	// "Dikeluarkan di <kota>" is per signature, not a fixed account field: it
	// rides on the request as a query param next to `reason`. Absent -> the
	// line is simply omitted from the caption.
	issuedPlace := strings.TrimSpace(r.URL.Query().Get("issued_place"))

	stamped, err := stampQR(body, places, coverData{
		PublicID:  res.PublicID,
		VerifyURL: s.qrTarget(r, res.PublicID), // QR -> the server address the signer is logged into
	}, captionData{
		FullName:    firstNonEmpty(acc.FullName, acc.DisplayName),
		Position:    acc.Position,
		NIP:         acc.NIP,
		IssuedPlace: issuedPlace,
		DateText:    idDate(jakartaNow()),
	})
	if err != nil {
		s.audit("stamp.apply", c, res.DeviceID, "fail", err.Error())
		writeErr(w, http.StatusUnprocessableEntity,
			"PDF ini tidak bisa diproses untuk penempelan QR (mungkin memakai fitur seperti "+
				"Content Credentials/C2PA, enkripsi, atau formulir yang kompleks). "+
				"Cetak ulang ke PDF (Print → Simpan sebagai PDF) lalu coba lagi.")
		return
	}
	s.audit("stamp.apply", c, res.DeviceID, "ok", res.PublicID)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("X-QR-Stamp", "applied")
	_, _ = w.Write(stamped)
}

type coverData struct {
	PublicID, VerifyURL string
}

// sanitizePDF re-reads pdf WITHOUT pdfcpu's spec validation, removes the
// document-level attachment / associated-file entries (which is where a C2PA
// manifest lives, and what the validator most often rejects), and writes a
// clean copy. The signed document does not need those attachments.
func sanitizePDF(pdf []byte, conf *model.Configuration) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sanitize: %v", r)
		}
	}()
	ctx, err := pdfcpu.ReadContext(bytes.NewReader(pdf), conf)
	if err != nil {
		return nil, err
	}
	if root, e := ctx.Catalog(); e == nil {
		delete(root, "Names")
		delete(root, "AF")
	}
	var buf bytes.Buffer
	if err = pdfcpu.WriteContext(ctx, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// parseStampPlacements reads the placement list for one /stamp call. The
// primary form is a URL-encoded JSON array in ?stamps= (one entry per QR box).
// When that is absent it falls back to the legacy single ?page&x&y&w params so
// older apps keep working (§2b).
func parseStampPlacements(r *http.Request) []stampPlacement {
	if raw := strings.TrimSpace(r.URL.Query().Get("stamps")); raw != "" {
		var arr []struct {
			Page int     `json:"page"`
			X    float64 `json:"x"`
			Y    float64 `json:"y"`
			W    float64 `json:"w"`
		}
		if err := json.Unmarshal([]byte(raw), &arr); err == nil && len(arr) > 0 {
			out := make([]stampPlacement, 0, len(arr))
			for _, e := range arr {
				out = append(out, stampPlacement{Page: e.Page, X: e.X, Y: e.Y, W: e.W})
			}
			return out
		}
	}
	return []stampPlacement{{
		Page: atoiDefault(r.URL.Query().Get("page"), 0),
		X:    atofDefault(r.URL.Query().Get("x"), 0.62),
		Y:    atofDefault(r.URL.Query().Get("y"), 0.80),
		W:    atofDefault(r.URL.Query().Get("w"), 0.26),
	}}
}

// stampQR draws one caption+QR stamp per placement onto pdf and returns the new
// bytes. The page count is unchanged; every placement's image is embedded in a
// single pdfcpu.Create pass. Any failure is returned so hStamp can tell the
// user the PDF is unsupported. An entry that cannot be placed on the page is a
// hard error (§2b).
func stampQR(pdf []byte, places []stampPlacement, d coverData, cap captionData) ([]byte, error) {
	if len(places) == 0 {
		return nil, fmt.Errorf("tidak ada titik QR")
	}
	conf := model.NewDefaultConfiguration() // ValidationRelaxed

	pageCount, err := pdfcpu.PageCount(bytes.NewReader(pdf), conf)
	if err != nil {
		// Real-world PDFs sometimes carry catalog entries pdfcpu's validator
		// rejects (e.g. a C2PA / Content Credentials manifest). Read without
		// validation, drop the attachment tree, and retry on the clean copy.
		if clean, cerr := sanitizePDF(pdf, conf); cerr == nil {
			if pc, perr := pdfcpu.PageCount(bytes.NewReader(clean), conf); perr == nil {
				pdf, pageCount, err = clean, pc, nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("gagal membaca PDF: %w", err)
		}
	}

	dims, err := pdfcpu.PageDims(bytes.NewReader(pdf), conf)
	if err != nil || len(dims) != pageCount {
		return nil, fmt.Errorf("gagal membaca ukuran halaman: %w", err)
	}

	tmp, err := os.MkdirTemp("", "pqc-stamp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	qrContent := d.VerifyURL
	if qrContent == "" {
		qrContent = d.PublicID
	}
	png, err := buildStampPNG(qrContent, cap, 900)
	if err != nil {
		return nil, fmt.Errorf("menyusun stempel: %w", err)
	}
	pngPath := filepath.Join(tmp, "stamp.png")
	if err := os.WriteFile(pngPath, png, 0o600); err != nil {
		return nil, err
	}
	src := filepath.ToSlash(pngPath)

	byPage := map[int][]cpImage{}
	for _, p := range places {
		page := p.Page
		if page < 1 || page > pageCount {
			page = pageCount // default / 0 -> last page
		}
		pw, ph := dims[page-1].Width, dims[page-1].Height

		// Clamp the fractional box so it always lands fully on the page.
		wf := clampf(p.W, 0.06, 0.9)
		boxW := wf * pw
		boxH := boxW * stampAspect
		if boxH > ph*0.9 {
			boxH = ph * 0.9
			boxW = boxH / stampAspect
		}
		if boxW <= 0 || boxH <= 0 {
			return nil, fmt.Errorf("titik QR di luar halaman")
		}
		xf := clampf(p.X, 0, 1)
		yf := clampf(p.Y, 0, 1)
		llx := clampf(xf*pw, 0, math.Max(0, pw-boxW))
		// app coordinates have Y growing downward from the top; pdfcpu's origin
		// is bottom-left.
		lly := clampf(ph-yf*ph-boxH, 0, math.Max(0, ph-boxH))

		byPage[page] = append(byPage[page], cpImage{
			Src:    src,
			Pos:    [2]float64{round2(llx), round2(lly)},
			Width:  round2(boxW),
			Height: round2(boxH),
		})
	}

	pages := make(map[string]cpPage, len(byPage))
	for page, imgs := range byPage {
		pages[strconv.Itoa(page)] = cpPage{Content: cpContent{Image: imgs}}
	}
	desc, err := json.Marshal(cpDoc{Origin: "LowerLeft", Pages: pages})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := pdfcpu.Create(bytes.NewReader(pdf), bytes.NewReader(desc), &out, conf); err != nil {
		return nil, fmt.Errorf("menempel QR: %w", err)
	}
	return out.Bytes(), nil
}

// idMonths are the Indonesian month names, index 0 = Januari.
var idMonths = [...]string{
	"Januari", "Februari", "Maret", "April", "Mei", "Juni",
	"Juli", "Agustus", "September", "Oktober", "November", "Desember",
}

func idMonth(m time.Month) string { return idMonths[int(m)-1] }

// idDate formats t as an Indonesian long date, e.g. "8 September 2026".
func idDate(t time.Time) string {
	return fmt.Sprintf("%d %s %d", t.Day(), idMonth(t.Month()), t.Year())
}

// jakartaNow is the current wall time in Asia/Jakarta. The Alpine runtime image
// carries tzdata; if the zone still cannot be loaded we fall back to a fixed
// +07:00 offset (WIB has no DST).
func jakartaNow() time.Time {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		loc = time.FixedZone("WIB", 7*3600)
	}
	return time.Now().In(loc)
}

// --- pdfcpu "create" JSON (tiny subset: one image on an existing page) ---

type cpImage struct {
	Src    string     `json:"src"`
	Pos    [2]float64 `json:"pos"`
	Width  float64    `json:"width,omitempty"`
	Height float64    `json:"height,omitempty"`
}
type cpContent struct {
	Image []cpImage `json:"image,omitempty"`
}
type cpPage struct {
	Content cpContent `json:"content"`
}
type cpDoc struct {
	Origin string            `json:"origin"`
	Pages  map[string]cpPage `json:"pages"`
}

func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

func atofDefault(s string, def float64) float64 {
	if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return v
	}
	return def
}

func clampf(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
