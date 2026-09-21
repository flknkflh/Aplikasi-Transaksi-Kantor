package api

import (
	"embed"
	"net/http"
)

// The super-admin page is static files served under its own strict CSP: no inline
// script or style, no third-party origin, not embeddable in a frame. It talks only
// to /api/v1/superadmin/*.
//
//go:embed superadmin/index.html superadmin/superadmin.js superadmin/superadmin.css
var superAdminFS embed.FS

const superAdminCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func (s *Server) mountSuperAdminPage(mux *http.ServeMux) {
	serve := func(name, ctype string) http.HandlerFunc {
		body, _ := superAdminFS.ReadFile("superadmin/" + name)
		return func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Type", ctype)
			h.Set("Content-Security-Policy", superAdminCSP)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cache-Control", "no-store")
			h.Set("X-Robots-Tag", "noindex, nofollow")
			_, _ = w.Write(body)
		}
	}
	mux.HandleFunc("GET /superadmin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/superadmin/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /superadmin/{$}", serve("index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /superadmin/superadmin.js", serve("superadmin.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /superadmin/superadmin.css", serve("superadmin.css", "text/css; charset=utf-8"))
}
