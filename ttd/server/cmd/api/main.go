// Command api runs the PQC PDF Sign V1 receiver server (Rencana V1 §17, §22).
//
// It accepts already-signed PDFs, re-verifies them strictly against the
// configured Root CA, stores metadata + the object, and serves the public
// verifier. It has NO endpoint that signs a PDF for a user (§1, §17.5).
//
// Backend selection:
//   - PQC_DATABASE_URL set  -> PostgreSQL (schema auto-applied)
//   - PQC_S3_ENDPOINT set   -> signed PDFs go to MinIO/S3, else the DB
//   - neither               -> in-memory (dev / tests)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// tlsConfig, when both cert/key are given, is TLS 1.3-only with post-quantum
// hybrid key exchange preferred (docs/adr/0009): Go's crypto/tls has offered
// X25519MLKEM768 by default since Go 1.24 and added SecP256r1MLKEM768 in Go
// 1.26 — listed explicitly here so it is a deliberate choice, not an implicit
// default a future GODEBUG flag or Go version could silently change. Classical
// X25519/P-256 stay listed too so a client without PQC support still connects
// (graceful degradation, not a hard requirement).
func tlsConfigFor(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert/key: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,    // hybrid: X25519 + ML-KEM-768 (post-quantum)
			tls.SecP256r1MLKEM768, // hybrid: P-256 + ML-KEM-768 (post-quantum)
			tls.X25519,            // classical fallback
			tls.CurveP256,         // classical fallback
		},
	}, nil
}

func main() {
	addr := flag.String("addr", envOr("PQC_ADDR", ":8080"), "listen address")
	verifyAddr := flag.String("verify-addr", envOr("PQC_VERIFY_ADDR", ""), "if set, also serve a verification-ONLY site (upload page + /api/v1/verify + QR pages) on this address, no auth")
	// TLS is additive, not a replacement for -addr/-verify-addr: set these to also
	// serve the SAME routes over HTTPS on their own address, so nothing that
	// already talks to the plain HTTP port breaks (docs/adr/0009).
	tlsAddr := flag.String("tls-addr", envOr("PQC_TLS_ADDR", ""), "if set (with -tls-cert/-tls-key), also serve the main site over HTTPS (TLS 1.3, hybrid post-quantum key exchange) on this address")
	verifyTLSAddr := flag.String("verify-tls-addr", envOr("PQC_VERIFY_TLS_ADDR", ""), "if set (with -verify-addr set and -tls-cert/-tls-key), also serve the verify-only site over HTTPS on this address")
	tlsCert := flag.String("tls-cert", os.Getenv("PQC_TLS_CERT_FILE"), "TLS certificate PEM file (required if -tls-addr or -verify-tls-addr is set)")
	tlsKey := flag.String("tls-key", os.Getenv("PQC_TLS_KEY_FILE"), "TLS private key PEM file (required if -tls-addr or -verify-tls-addr is set)")
	rootPath := flag.String("root-ca", os.Getenv("PQC_ROOT_CA_PEM"), "Root CA PEM file (required)")
	chainPath := flag.String("ca-chain", os.Getenv("PQC_CA_CHAIN_PEM"), "Root+Intermediate chain PEM file")
	crlPath := flag.String("crl", os.Getenv("PQC_CRL_PEM"), "current CRL PEM file")
	baseURL := flag.String("public-base-url", envOr("PQC_PUBLIC_BASE_URL", "http://localhost:8443"), "public verifier base URL")
	flag.Parse()

	if *rootPath == "" {
		log.Fatal("api: -root-ca (or PQC_ROOT_CA_PEM) is required")
	}
	secret := []byte(os.Getenv("PQC_JWT_SECRET"))
	if len(secret) < 16 {
		log.Fatal("api: PQC_JWT_SECRET must be set to at least 16 bytes")
	}
	allowInsecureDev := boolEnv("ALLOW_INSECURE_DEV_SECRETS")
	rejectInsecureSecret("PQC_JWT_SECRET", string(secret), allowInsecureDev)

	cfg := api.Config{JWTSecret: secret, PublicBaseURL: *baseURL, AccessTTL: 15 * time.Minute}
	cfg.SuperAdminUsername = envOr("PQC_SUPERADMIN_USERNAME", "superadmin")
	cfg.SuperAdminPassword = os.Getenv("PQC_SUPERADMIN_PASSWORD")    // "" -> generated + logged once
	cfg.BootstrapAdminEmail = os.Getenv("PQC_BOOTSTRAP_ADMIN_EMAIL") // seed/dev only; see ensureBootstrapAdmin
	cfg.BootstrapAdminPassword = os.Getenv("PQC_BOOTSTRAP_ADMIN_PASSWORD")
	rejectInsecureSecret("PQC_SUPERADMIN_PASSWORD", cfg.SuperAdminPassword, allowInsecureDev)
	rejectInsecureSecret("PQC_BOOTSTRAP_ADMIN_PASSWORD", cfg.BootstrapAdminPassword, allowInsecureDev)
	cfg.MaxUploadBytes = mbEnv("PQC_MAX_UPLOAD_MB", 25)   // absolute ceiling
	cfg.MaxStampBytes = mbEnv("PQC_MAX_STAMP_MB", 150)    // server QR stamp (pdfcpu) cap
	cfg.MaxVerifyBytes = mbEnv("PQC_MAX_VERIFY_MB", 350)  // strict re-verify cap; larger = store-only
	cfg.WebDir = os.Getenv("PQC_WEB_DIR")                 // "" -> embedded browser client
	cfg.OfficeUpstream = os.Getenv("PQC_OFFICE_UPSTREAM") // e.g. http://ledger-api:8080
	cfg.OfficeSecret = os.Getenv("PQC_OFFICE_SECRET")
	rejectInsecureSecret("PQC_OFFICE_SECRET", cfg.OfficeSecret, allowInsecureDev)
	cfg.ServerName = envOr("PQC_SERVER_NAME", "Server Arsip")
	cfg.UploadDir = os.Getenv("PQC_UPLOAD_DIR") // "" -> os.TempDir()
	if boolEnv("PQC_RATE_LIMIT_DISABLED") {
		cfg.RateLimits = &api.RateLimits{} // dev / scripted runs only
	}
	if bin := os.Getenv("PQC_DEV_LAB_CA_ADMIN"); bin != "" {
		cfg.LabIssuer = &api.LabIssuer{
			Bin:        bin,
			Dir:        envOr("PQC_DEV_LAB_CA_DIR", "ca"),
			Passphrase: os.Getenv("PQC_CA_PASSPHRASE"),
			Operator:   envOr("PQC_CA_OPERATOR", "dev-admin-console"),
		}
		log.Printf("api: DEV lab issuer ENABLED (%s, dir %s) — must never be set in production",
			cfg.LabIssuer.Bin, cfg.LabIssuer.Dir)
	}
	var err error
	if cfg.RootCAPEM, err = os.ReadFile(*rootPath); err != nil {
		log.Fatalf("api: read root CA: %v", err)
	}
	if *chainPath != "" {
		if cfg.CAChainPEM, err = os.ReadFile(*chainPath); err != nil {
			log.Fatalf("api: read CA chain: %v", err)
		}
	}
	if *crlPath != "" {
		if cfg.CRLPEM, err = os.ReadFile(*crlPath); err != nil {
			log.Fatalf("api: read CRL: %v", err)
		}
	}

	st, backend, err := openStore()
	if err != nil {
		log.Fatalf("api: store: %v", err)
	}

	srv, err := api.New(st, cfg)
	if err != nil {
		log.Fatalf("api: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	var verifySrv *http.Server
	if *verifyAddr != "" {
		verifySrv = &http.Server{
			Addr:              *verifyAddr,
			Handler:           srv.VerifyRoutes(),
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	// TLS listeners (docs/adr/0009): additive, on their own address(es), the
	// plain HTTP ones above are untouched either way.
	var tlsSrv, verifyTLSSrv *http.Server
	if *tlsAddr != "" || *verifyTLSAddr != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("api: -tls-cert and -tls-key (or PQC_TLS_CERT_FILE/PQC_TLS_KEY_FILE) are required when -tls-addr or -verify-tls-addr is set")
		}
		tc, err := tlsConfigFor(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("api: %v", err)
		}
		if *tlsAddr != "" {
			tlsSrv = &http.Server{Addr: *tlsAddr, Handler: srv.Routes(), TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second}
		}
		if *verifyTLSAddr != "" {
			if verifySrv == nil {
				log.Fatal("api: -verify-tls-addr requires -verify-addr to also be set")
			}
			verifyTLSSrv = &http.Server{Addr: *verifyTLSAddr, Handler: srv.VerifyRoutes(), TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		fmt.Printf("pqc-pdf-sign receiver API listening on %s (store: %s)\n", *addr, backend)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("api: serve: %v", err)
		}
	}()
	if verifySrv != nil {
		go func() {
			fmt.Printf("pqc-pdf-sign verification-only site listening on %s\n", verifySrv.Addr)
			if err := verifySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("api: verify serve: %v", err)
			}
		}()
	}
	if tlsSrv != nil {
		go func() {
			fmt.Printf("pqc-pdf-sign receiver API listening on %s (HTTPS, TLS 1.3 hybrid PQC)\n", tlsSrv.Addr)
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("api: tls serve: %v", err)
			}
		}()
	}
	if verifyTLSSrv != nil {
		go func() {
			fmt.Printf("pqc-pdf-sign verification-only site listening on %s (HTTPS, TLS 1.3 hybrid PQC)\n", verifyTLSSrv.Addr)
			if err := verifyTLSSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("api: verify tls serve: %v", err)
			}
		}()
	}
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	if verifySrv != nil {
		_ = verifySrv.Shutdown(shutCtx)
	}
	if tlsSrv != nil {
		_ = tlsSrv.Shutdown(shutCtx)
	}
	if verifyTLSSrv != nil {
		_ = verifyTLSSrv.Shutdown(shutCtx)
	}
}

func openStore() (api.Store, string, error) {
	dsn := os.Getenv("PQC_DATABASE_URL")
	if dsn == "" {
		return store.NewMemory(), "in-memory", nil
	}
	var objs store.ObjectStore
	label := "postgres"
	if ep := os.Getenv("PQC_S3_ENDPOINT"); ep != "" {
		var err error
		objs, err = store.NewS3Objects(store.S3Config{
			Endpoint:  ep,
			Region:    envOr("PQC_S3_REGION", "us-east-1"),
			Bucket:    envOr("PQC_S3_BUCKET", "pqc-pdf-sign"),
			AccessKey: os.Getenv("PQC_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("PQC_S3_SECRET_KEY"),
			UseSSL:    boolEnv("PQC_S3_USE_SSL"),
		})
		if err != nil {
			return nil, "", err
		}
		label = "postgres + s3"
	} else if dir := os.Getenv("PQC_OBJECT_DIR"); dir != "" {
		// Signed PDFs go to a mounted volume, not a Postgres bytea value
		// (bytea caps at 1 GiB and buffers whole). Needed for large documents.
		var err error
		if objs, err = store.NewFSObjects(dir); err != nil {
			return nil, "", err
		}
		label = "postgres + fs:" + dir
	}
	pg, err := store.OpenPostgres(dsn, objs)
	if err != nil {
		return nil, "", err
	}
	return pg, label, nil
}

func mbEnv(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n << 20
		}
	}
	return def << 20
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func boolEnv(k string) bool {
	b, _ := strconv.ParseBool(os.Getenv(k))
	return b
}

// rejectInsecureSecret hard-fails startup if value is empty-but-required-elsewhere
// (that is checked separately) or matches a known placeholder/example value —
// several of which are the exact literals this repo's own .env.example and
// deploy/office/docker-compose.yml ship as convenience dev defaults (docs/adr/0006
// security checklist #9: a real deployment must never silently start on one of
// these). allowInsecureDev, set via ALLOW_INSECURE_DEV_SECRETS=true, is the
// explicit opt-in deploy/office/docker-compose.yml uses for local/dev runs.
func rejectInsecureSecret(envName, value string, allowInsecureDev bool) {
	if value == "" || !looksLikeDefaultSecret(value) {
		return
	}
	if allowInsecureDev {
		log.Printf("api: WARNING %s is a known placeholder/example value — allowed only because ALLOW_INSECURE_DEV_SECRETS=true; never set that in production", envName)
		return
	}
	log.Fatalf("api: %s looks like a placeholder/example value shipped in this repo's own docs — set a real secret (see .env.example), or set ALLOW_INSECURE_DEV_SECRETS=true for local dev only", envName)
}

func looksLikeDefaultSecret(v string) bool {
	lower := strings.ToLower(v)
	for _, marker := range []string{
		"change_me", "change-me", "changeme", "ganti_ini", "ganti-ini",
		"dev_only", "dev-only", "example", "placeholder", "insecure",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	switch lower {
	case "admin12345", "pqc", "postgres", "password", "secret", "12345678":
		return true
	}
	return false
}
