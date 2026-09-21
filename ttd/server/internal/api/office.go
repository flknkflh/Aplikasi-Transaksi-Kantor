package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Office integration (docs/adr/0003-office-app.md). The TTD server stays the
// place where people log in; the office (transaction) service is reached
// through it so the browser has ONE origin and ONE session:
//
//	browser --(Bearer JWT)--> /office/*  --proxy--> office service
//	                              vouches for the identity with a shared secret
//	office service --(secret)--> /internal/office/signatures/{id}[/document]
//	                              asks TTD "who signed what?" (source of truth)
//
// Nothing here can sign: the server still has no endpoint that produces a
// signature, and the internal endpoints only READ records the server already
// verified when the signed PDF was submitted.

// mountOffice registers the proxy and the internal read endpoints when both
// Config.OfficeUpstream and Config.OfficeSecret are set; otherwise it is a no-op.
func (s *Server) mountOffice(mux *http.ServeMux) {
	if s.cfg.OfficeUpstream == "" || s.cfg.OfficeSecret == "" {
		return
	}
	if len(s.cfg.OfficeSecret) < 16 {
		log.Printf("api: PQC_OFFICE_SECRET must be at least 16 bytes — office routes disabled")
		return
	}
	target, err := url.Parse(s.cfg.OfficeUpstream)
	if err != nil || target.Host == "" {
		log.Printf("api: PQC_OFFICE_UPSTREAM %q is not a valid URL — office routes disabled", s.cfg.OfficeUpstream)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("api: office upstream: %v", err)
		writeErr(w, http.StatusBadGateway, "layanan transaksi tidak dapat dihubungi")
	}
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		director(r)
		r.Host = target.Host
	}

	mux.HandleFunc("/office/", s.user(func(w http.ResponseWriter, r *http.Request) {
		c := claims(r)
		acc, err := s.st.Account(c.Sub)
		if err != nil || acc.Status != store.AccountActive {
			writeErr(w, http.StatusForbidden, "akun tidak aktif")
			return
		}
		// Never forward the caller's own credentials or any header that could
		// spoof an identity; the office service trusts only what we set here.
		r = r.Clone(r.Context())
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-office-") {
				r.Header.Del(k)
			}
		}
		r.Header.Del("Authorization")
		// The peer address the ledger records is the real one: drop any client-supplied
		// chain so ReverseProxy sets X-Forwarded-For from the actual connection.
		r.Header.Del("X-Forwarded-For")
		name := acc.DisplayName
		if name == "" {
			name = acc.FullName
		}
		r.Header.Set("X-Office-Secret", s.cfg.OfficeSecret)
		r.Header.Set("X-Office-Account", acc.ID)
		r.Header.Set("X-Office-Email", acc.Email)
		r.Header.Set("X-Office-Name", name)
		r.Header.Set("X-Office-Role", acc.Role)
		// Uploads arrive in 8 MiB chunks (archive protocol); the ledger service enforces its own caps.
		r.Body = http.MaxBytesReader(w, r.Body, 72<<20)
		proxy.ServeHTTP(w, r)
	}))

	// Public receipt check: anyone holding a receipt id can see it is genuine. The
	// receipt id is an unguessable capability; the request is rate-limited by IP and
	// only ever forwarded to the one read-only upstream route.
	mux.HandleFunc("GET /api/v1/public/receipts/{receipt_id}", s.limit(s.rlVerify, byIP, func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-office-") {
				r.Header.Del(k)
			}
		}
		r.Header.Del("Authorization")
		r.Header.Del("X-Forwarded-For")
		r.Header.Set("X-Office-Secret", s.cfg.OfficeSecret)
		r.URL.Path = "/public/receipts/" + r.PathValue("receipt_id")
		r.URL.RawPath = ""
		proxy.ServeHTTP(w, r)
	}))

	mux.HandleFunc("GET /internal/office/signatures/{public_id}", s.officeSecret(s.hOfficeSignature))
	mux.HandleFunc("GET /internal/office/signatures/{public_id}/document", s.officeSecret(s.hOfficeSignatureDocument))
}

// hPublicServer tells a not-yet-logged-in user which server they are talking to, so
// they can confirm it is the one they meant to send data to.
func (s *Server) hPublicServer(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	writeJSON(w, http.StatusOK, map[string]any{
		"server_name": s.cfg.ServerName, "host": r.Host, "https": secure,
		"office_enabled": s.cfg.OfficeUpstream != "" && len(s.cfg.OfficeSecret) >= 16,
	})
}

func (s *Server) officeSecret(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Office-Secret")), []byte(s.cfg.OfficeSecret)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r)
	}
}

// hOfficeSignature returns the server's record of one signature: who made it
// (account id, from the authenticated reservation — never from the client),
// the hashes, and whether the server's strict re-verification accepted it.
func (s *Server) hOfficeSignature(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such signature")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"public_id":           sig.PublicID,
		"account_id":          sig.AccountID,
		"original_sha512":     sig.OriginalSHA512,
		"signed_sha512":       sig.SignedSHA512,
		"verification_status": sig.VerificationStatus,
		"verification_url":    s.verifyURL(sig.PublicID),
	})
}

func (s *Server) hOfficeSignatureDocument(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such signature")
		return
	}
	b, err := s.st.GetObject(sig.StorageObjectKey)
	if err != nil {
		writeErr(w, http.StatusNotFound, "document not available")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}
