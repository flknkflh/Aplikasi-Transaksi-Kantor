package api

import (
	_ "embed"
	"net/http"
)

//go:embed adminui.html
var adminUIHTML []byte

// hAdminUI serves the single-file operator console (Rencana V1 §14) at /admin.
// It is plain static HTML+JS that only calls the authenticated /api/v1/*
// endpoints; it holds no secret of its own.
func (s *Server) hAdminUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(adminUIHTML)
}
