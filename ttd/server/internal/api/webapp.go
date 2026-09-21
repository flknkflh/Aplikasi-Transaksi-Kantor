package api

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// The browser client (ttd/web) — built by web/build.sh into ./webapp — is
// served same-origin under /app/. It only calls the existing /api/v1/* routes;
// there is still NO server endpoint that signs anything (the device key never
// reaches the server, docs/architecture.md). all: keeps the .gitkeep so the
// package compiles before the client has been built.
//
//go:embed all:webapp
var webappFS embed.FS

// webCSP is deliberately strict. The client has no inline script, style or
// handler, talks only to its own origin, and needs 'wasm-unsafe-eval' solely to
// instantiate pqcsign.wasm (no eval/new Function). This is the main defence of
// the in-browser key against XSS (docs/threat-model-browser.md).
const webCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
	"img-src 'self' data: blob:; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

type webAsset struct {
	body  []byte
	gz    []byte // nil when not worth compressing
	ctype string
	etag  string
}

// mountWebApp serves the browser client at /app/. dir, when non-empty
// (PQC_WEB_DIR), overrides the embedded copy — handy while developing the
// client without rebuilding the server; it is read once at startup.
func (s *Server) mountWebApp(mux *http.ServeMux, dir string) {
	assets := loadWebAssets(dir)
	if _, ok := assets["index.html"]; !ok {
		log.Printf("api: browser client not built (run ttd/web/build.sh); /app/ will answer 503")
	}
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/app/")), "/")
		if name == "" {
			name = "index.html"
		}
		a, ok := assets[name] // a map lookup: no filesystem access, so no path traversal
		if !ok {
			if len(assets) == 0 {
				http.Error(w, "browser client not built: run ttd/web/build.sh", http.StatusServiceUnavailable)
				return
			}
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", a.ctype)
		h.Set("Content-Security-Policy", webCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cache-Control", "no-cache") // always revalidate: the client is security-critical code
		h.Set("ETag", a.etag)
		h.Add("Vary", "Accept-Encoding")
		if r.Header.Get("If-None-Match") == a.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		body := a.body
		if a.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			h.Set("Content-Encoding", "gzip")
			body = a.gz
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
	})
}

func loadWebAssets(dir string) map[string]*webAsset {
	var fsys fs.FS
	if dir != "" {
		fsys = os.DirFS(dir)
	} else {
		sub, err := fs.Sub(webappFS, "webapp")
		if err != nil {
			return nil
		}
		fsys = sub
	}
	out := map[string]*webAsset{}
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(path.Base(p), ".") {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(b)
		a := &webAsset{body: b, ctype: webContentType(p), etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
		if len(b) > 1024 && !strings.HasPrefix(a.ctype, "image/") {
			var buf bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			_, _ = zw.Write(b)
			_ = zw.Close()
			if buf.Len() < len(b) {
				a.gz = buf.Bytes()
			}
		}
		out[p] = a
		return nil
	})
	return out
}

func webContentType(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".wasm":
		return "application/wasm"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	}
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}
