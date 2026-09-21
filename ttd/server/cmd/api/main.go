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
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

func main() {
	addr := flag.String("addr", envOr("PQC_ADDR", ":8080"), "listen address")
	verifyAddr := flag.String("verify-addr", envOr("PQC_VERIFY_ADDR", ""), "if set, also serve a verification-ONLY site (upload page + /api/v1/verify + QR pages) on this address, no auth")
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

	cfg := api.Config{JWTSecret: secret, PublicBaseURL: *baseURL, AccessTTL: 15 * time.Minute}
	cfg.SuperAdminUsername = envOr("PQC_SUPERADMIN_USERNAME", "superadmin")
	cfg.SuperAdminPassword = os.Getenv("PQC_SUPERADMIN_PASSWORD") // "" -> generated + logged once
	cfg.MaxUploadBytes = mbEnv("PQC_MAX_UPLOAD_MB", 25)           // absolute ceiling
	cfg.MaxStampBytes = mbEnv("PQC_MAX_STAMP_MB", 150)            // server QR stamp (pdfcpu) cap
	cfg.MaxVerifyBytes = mbEnv("PQC_MAX_VERIFY_MB", 350)          // strict re-verify cap; larger = store-only
	cfg.UploadDir = os.Getenv("PQC_UPLOAD_DIR")                   // "" -> os.TempDir()
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
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	if verifySrv != nil {
		_ = verifySrv.Shutdown(shutCtx)
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
