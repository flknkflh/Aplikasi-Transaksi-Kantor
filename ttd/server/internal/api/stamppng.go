package api

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"

	qrcode "github.com/skip2/go-qrcode"
)

// stampAspect is height / width of the QR stamp. The stamp is now a landscape
// box holding a caption block plus the QR square on the right, so it is wider
// than tall. The clients size their draggable box with the same ratio
// (STAMP_ASPECT).
const stampAspect = 0.42

// captionData is the text drawn beside the QR. FullName/Position/NIP are the
// signer's fixed identity, taken from the server-side Account record (never the
// client, so they cannot be spoofed). IssuedPlace and DateText are per
// signature: the place rides in on the /stamp request, the date is server time.
// Empty fields drop their line.
type captionData struct {
	FullName    string
	Position    string
	NIP         string
	IssuedPlace string
	DateText    string // already formatted, e.g. "8 September 2026"
}

var (
	regularFont = mustParseFont(goregular.TTF)
	boldFont    = mustParseFont(gobold.TTF)
)

func mustParseFont(ttf []byte) *opentype.Font {
	f, err := opentype.Parse(ttf)
	if err != nil {
		panic("stamppng: parse embedded font: " + err.Error())
	}
	return f
}

func face(f *opentype.Font, sizePx float64) font.Face {
	fc, err := opentype.NewFace(f, &opentype.FaceOptions{Size: sizePx, DPI: 72, Hinting: font.HintingFull})
	if err != nil {
		// FaceOptions with a positive size never fails in practice; fall back
		// to a tiny face rather than panicking inside a request.
		fc, _ = opentype.NewFace(f, &opentype.FaceOptions{Size: 8, DPI: 72})
	}
	return fc
}

// buildStampPNG renders the e-signature stamp: a bordered white landscape box
// with the caption block on the left and the QR square on the right. widthPx
// controls resolution only — the PDF placement scales the whole image to the
// box the signer drew. When cap has no usable text the QR still renders on its
// own so old-style bare-QR callers keep working.
func buildStampPNG(qrContent string, cap captionData, widthPx int) ([]byte, error) {
	if widthPx < 480 {
		widthPx = 900
	}
	heightPx := int(float64(widthPx)*stampAspect + 0.5)

	qc, err := qrcode.New(qrContent, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	qc.DisableBorder = true

	img := image.NewRGBA(image.Rect(0, 0, widthPx, heightPx))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)

	pad := heightPx / 12
	if pad < 6 {
		pad = 6
	}

	// QR square on the right, inset by pad on three sides.
	qrSide := heightPx - 2*pad
	if qrSide < 16 {
		qrSide = heightPx
	}
	qrImg := qc.Image(qrSide)
	qrX0 := widthPx - pad - qrSide
	qrY0 := (heightPx - qrSide) / 2
	// small white quiet zone behind the QR so it scans on a coloured area
	draw.Draw(img, image.Rect(qrX0-pad/2, qrY0-pad/2, qrX0+qrSide+pad/2, qrY0+qrSide+pad/2),
		image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(qrX0, qrY0, qrX0+qrSide, qrY0+qrSide), qrImg, qrImg.Bounds().Min, draw.Over)

	// Caption block on the left, if we have anything to say.
	lines := captionLines(cap)
	if len(lines) > 0 {
		textX0 := pad + pad/2
		textW := qrX0 - pad - textX0
		if textW > 40 {
			drawCaption(img, lines, textX0, pad, textW, heightPx-2*pad)
		}
	}

	drawBorder(img, 2, color.RGBA{0x33, 0x33, 0x33, 0xff})

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// captionLine is one rendered line: its text and whether it is bold.
type captionLine struct {
	text string
	bold bool
}

// captionLines assembles the caption in order, skipping any line whose field
// is empty (§2c). The header + name are the anchor; a stamp with only a name
// still renders.
func captionLines(c captionData) []captionLine {
	name := strings.TrimSpace(c.FullName)
	var out []captionLine
	if name != "" {
		out = append(out,
			captionLine{text: "Ditandatangani secara elektronik oleh:"},
			captionLine{text: name, bold: true},
		)
	}
	if p := strings.TrimSpace(c.Position); p != "" {
		out = append(out, captionLine{text: p}) // wrapped later
	}
	if n := strings.TrimSpace(c.NIP); n != "" {
		out = append(out, captionLine{text: "NIP. " + n})
	}
	if pl := strings.TrimSpace(c.IssuedPlace); pl != "" {
		out = append(out, captionLine{text: "Dikeluarkan di " + pl})
	}
	if d := strings.TrimSpace(c.DateText); d != "" {
		out = append(out, captionLine{text: "Pada tanggal " + d})
	}
	return out
}

// drawCaption fits the lines into (maxW x maxH) starting at (x0,y0). It picks
// the largest body size (from a fixed ladder) whose wrapped block fits, wraps
// the long "position" line to maxW, then vertically centres the block.
func drawCaption(dst *image.RGBA, lines []captionLine, x0, y0, maxW, maxH int) {
	ink := color.RGBA{0x11, 0x11, 0x11, 0xff}

	for _, size := range []float64{26, 24, 22, 20, 18, 16, 14, 12, 10} {
		body := face(regularFont, size)
		bold := face(boldFont, size)
		head := face(regularFont, size*0.82)

		type placed struct {
			text string
			f    font.Face
		}
		var ps []placed
		for i, ln := range lines {
			f := body
			if ln.bold {
				f = bold
			}
			if i == 0 && !ln.bold { // the "Ditandatangani ..." header
				f = head
			}
			for _, w := range wrapText(f, ln.text, maxW) {
				ps = append(ps, placed{text: w, f: f})
			}
		}

		lineH := face(regularFont, size).Metrics().Height.Ceil()
		lineH = lineH*4/3 + 1
		total := lineH * len(ps)
		if total > maxH && size > 10 {
			continue // try a smaller size
		}

		top := y0
		if total < maxH {
			top += (maxH - total) / 2
		}
		baseline := top + lineH*3/4
		for _, p := range ps {
			drawString(dst, p.f, x0, baseline, p.text, ink)
			baseline += lineH
		}
		return
	}
}

func drawString(dst *image.RGBA, f font.Face, x, baseline int, s string, col color.Color) {
	d := &font.Drawer{
		Dst:  dst,
		Src:  image.NewUniform(col),
		Face: f,
		Dot:  fixed.Point26_6{X: fixed.I(x), Y: fixed.I(baseline)},
	}
	d.DrawString(s)
}

func stringWidth(f font.Face, s string) int {
	d := &font.Drawer{Face: f}
	return d.MeasureString(s).Ceil()
}

// wrapText greedily wraps s to maxW pixels using f's metrics. A single word
// wider than maxW is left on its own line (it will be clipped by the box).
func wrapText(f font.Face, s string, maxW int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if stringWidth(f, cur+" "+w) <= maxW {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	return append(lines, cur)
}

func drawBorder(img *image.RGBA, thick int, col color.Color) {
	b := img.Bounds()
	u := image.NewUniform(col)
	draw.Draw(img, image.Rect(b.Min.X, b.Min.Y, b.Max.X, b.Min.Y+thick), u, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(b.Min.X, b.Max.Y-thick, b.Max.X, b.Max.Y), u, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(b.Min.X, b.Min.Y, b.Min.X+thick, b.Max.Y), u, image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(b.Max.X-thick, b.Min.Y, b.Max.X, b.Max.Y), u, image.Point{}, draw.Src)
}
