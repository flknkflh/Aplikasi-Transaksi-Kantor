// Command api is the Fase 1 spike's REST API service: transactions, assets,
// approvals, documents, and the outbox worker that relays signed events to
// the Fabric ledger. See docs/adr/0001-fase1-spike-scope.md for scope.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"ledger/api/internal/config"
	"ledger/api/internal/fabricclient"
	"ledger/api/internal/httpapi"
	"ledger/api/internal/keystore"
	"ledger/api/internal/outbox"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("connect postgres", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := seedDemoData(ctx, db); err != nil {
		logger.Error("seed demo data", "error", err)
		os.Exit(1)
	}

	minioClient, err := minio.New(cfg.MinIOEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinIOAccessKey, cfg.MinIOSecretKey, ""),
		Secure: cfg.MinIOUseSSL,
	})
	if err != nil {
		logger.Error("connect minio", "error", err)
		os.Exit(1)
	}
	if err := ensureBucket(ctx, minioClient, cfg.MinIOBucket); err != nil {
		logger.Error("ensure minio bucket", "error", err)
		os.Exit(1)
	}

	ks, err := keystore.Open(cfg.KeystorePath, db)
	if err != nil {
		logger.Error("open keystore", "error", err)
		os.Exit(1)
	}

	fabric, err := fabricclient.Connect(cfg)
	if err != nil {
		logger.Error("connect fabric gateway", "error", err)
		os.Exit(1)
	}
	defer fabric.Close()

	pollInterval, err := time.ParseDuration(cfg.OutboxPollInterval)
	if err != nil {
		logger.Error("parse OUTBOX_POLL_INTERVAL", "error", err)
		os.Exit(1)
	}
	worker := outbox.NewWorker(db, fabric, pollInterval, cfg.OutboxMaxAttempts, logger)
	go worker.Run(ctx)

	server := &httpapi.Server{
		DB:          db,
		Keystore:    ks,
		MinIO:       minioClient,
		Bucket:      cfg.MinIOBucket,
		Application: cfg.Application,
		Environment: cfg.Environment,
		Logger:      logger,
	}

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: server.Routes(),
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	logger.Info("api listening", "addr", cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("http server", "error", err)
		os.Exit(1)
	}
}

func ensureBucket(ctx context.Context, client *minio.Client, bucket string) error {
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
}

// seedDemoData upserts a couple of demo organizations and user identities so
// the spike is usable without a real SSO/user-provisioning flow (PRD FR-001
// is explicitly Fase 2+ — see docs/adr/0001-fase1-spike-scope.md). Idempotent:
// safe to run on every startup.
func seedDemoData(ctx context.Context, db *pgxpool.Pool) error {
	orgs := []struct{ id, name, mspID string }{
		{"org-a", "Demo Organization A", "Org1MSP"},
	}
	for _, o := range orgs {
		if _, err := db.Exec(ctx, `
			INSERT INTO organization (id, name, msp_id) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO NOTHING`, o.id, o.name, o.mspID); err != nil {
			return err
		}
	}

	users := []struct{ id, name, role string }{
		{"requester-1", "Demo Requester", "requester"},
		{"approver-1", "Demo Approver One", "approver"},
		{"approver-2", "Demo Approver Two", "approver"},
		{"warehouse-1", "Demo Warehouse Operator", "warehouse_operator"},
		{"auditor-1", "Demo Auditor", "auditor"},
	}
	for _, u := range users {
		if _, err := db.Exec(ctx, `
			INSERT INTO user_identity (id, organization_id, display_name, role) VALUES ($1, 'org-a', $2, $3)
			ON CONFLICT (id) DO NOTHING`, u.id, u.name, u.role); err != nil {
			return err
		}
	}
	return nil
}
