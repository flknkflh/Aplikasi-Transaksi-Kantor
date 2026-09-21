// Command audit-service provides independent verification of ledger events
// and periodic checkpoints (PRD FR-010, FR-014, §6, §15). It queries the
// Fabric ledger directly, not Postgres, and re-verifies hybrid signatures
// itself — an admin who tampers with the operational database cannot fool
// it. See docs/adr/0001-fase1-spike-scope.md.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/jackc/pgx/v5/pgxpool"

	"ledger/audit-service/internal/checkpoint"
	"ledger/audit-service/internal/config"
	"ledger/audit-service/internal/fabricclient"
	"ledger/audit-service/internal/httpapi"
	"ledger/audit-service/internal/verify"
)

const checkpointInterval = 5 * time.Minute

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

	fabric, err := fabricclient.Connect(cfg)
	if err != nil {
		logger.Error("connect fabric gateway", "error", err)
		os.Exit(1)
	}
	defer fabric.Close()

	network := fabric.Network()

	go runPeriodicCheckpoints(ctx, logger, db, network, cfg.FabricChannelName)

	server := &httpapi.Server{
		DB:          db,
		Network:     network,
		Verifier:    &verify.Verifier{DB: db, Application: cfg.Application, Environment: cfg.Environment},
		ChannelName: cfg.FabricChannelName,
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

	logger.Info("audit-service listening", "addr", cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("http server", "error", err)
		os.Exit(1)
	}
}

// runPeriodicCheckpoints writes a fresh audit_checkpoint row on a fixed
// interval (PRD §15's checkpoint requirement) in addition to whatever an
// operator triggers manually via POST /checkpoints.
func runPeriodicCheckpoints(ctx context.Context, logger *slog.Logger, db *pgxpool.Pool, network *client.Network, channelName string) {
	ticker := time.NewTicker(checkpointInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			blockNumber, blockHash, err := checkpoint.Create(ctx, db, network, channelName)
			if err != nil {
				logger.Error("periodic checkpoint", "error", err)
				continue
			}
			logger.Info("checkpoint created", "block_number", blockNumber, "block_hash", blockHash)
		}
	}
}
