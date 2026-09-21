// Command indexer listens to Fabric chaincode commit events and updates the
// Postgres read model (PRD §6 "Indexer dan Event Worker", FR-009). It never
// writes to the ledger — only api/'s outbox worker does that — and never
// signs anything, so unlike api/ and audit-service/ it has no dependency on
// ledger/crypto or liboqs.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/jackc/pgx/v5/pgxpool"

	"ledger/indexer/internal/apply"
	"ledger/indexer/internal/checkpoint"
	"ledger/indexer/internal/config"
	"ledger/indexer/internal/fabricclient"
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

	fabric, err := fabricclient.Connect(cfg)
	if err != nil {
		logger.Error("connect fabric gateway", "error", err)
		os.Exit(1)
	}
	defer fabric.Close()

	done := make(chan struct{}, len(cfg.ChaincodeNames))
	for _, ccName := range cfg.ChaincodeNames {
		go func(chaincodeName string) {
			runListener(ctx, logger, db, fabric.Network, chaincodeName)
			done <- struct{}{}
		}(ccName)
	}

	for range cfg.ChaincodeNames {
		<-done
	}
}

// runListener subscribes to one chaincode's events from its last checkpoint
// and applies each one, reconnecting with backoff if the stream drops for
// any reason other than ctx being cancelled.
func runListener(ctx context.Context, logger *slog.Logger, db *pgxpool.Pool, network *client.Network, chaincodeName string) {
	backoff := time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		lastBlock, err := checkpoint.Load(ctx, db, chaincodeName)
		if err != nil {
			logger.Error("load checkpoint", "chaincode", chaincodeName, "error", err)
			sleepOrDone(ctx, backoff)
			continue
		}

		var opts []client.ChaincodeEventsOption
		if lastBlock > 0 {
			opts = append(opts, client.WithStartBlock(lastBlock))
		}
		events, err := network.ChaincodeEvents(ctx, chaincodeName, opts...)
		if err != nil {
			logger.Error("subscribe chaincode events", "chaincode", chaincodeName, "error", err)
			sleepOrDone(ctx, backoff)
			continue
		}

		logger.Info("listening for chaincode events", "chaincode", chaincodeName, "from_block", lastBlock)
		backoff = time.Second

	stream:
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					logger.Warn("chaincode event stream closed, reconnecting", "chaincode", chaincodeName)
					break stream
				}
				if err := applyEvent(ctx, db, event); err != nil {
					logger.Error("apply event", "chaincode", chaincodeName, "event", event.EventName, "error", err)
					// Deliberately do not advance the checkpoint past a
					// failed event — retrying the same event on the next
					// pass is safe (see package apply's idempotency note).
					continue
				}
				if err := checkpoint.Save(ctx, db, chaincodeName, event.BlockNumber); err != nil {
					logger.Error("save checkpoint", "chaincode", chaincodeName, "error", err)
				}
			}
		}
	}
}

func applyEvent(ctx context.Context, db *pgxpool.Pool, event *client.ChaincodeEvent) error {
	switch event.EventName {
	case "TransactionEventRecorded":
		return apply.TransactionEventRecorded(ctx, db, event.BlockNumber, event.TransactionID, event.Payload)
	case "CustodyEventRecorded":
		return apply.CustodyEventRecorded(ctx, db, event.BlockNumber, event.TransactionID, event.Payload)
	case "TransactionCreated", "AssetCreated", "ApprovalRecorded":
		// Read-model rows for these already exist from the API's own write
		// (PRD §5.1 steps 2/6); no additional read-model update is needed
		// for this spike beyond the commit confirmation the two cases above
		// provide. Recorded here only to prove the listener saw them.
		return logSeen(event)
	default:
		return logSeen(event)
	}
}

func logSeen(event *client.ChaincodeEvent) error {
	var preview map[string]interface{}
	_ = json.Unmarshal(event.Payload, &preview)
	slog.Default().Info("chaincode event observed", "chaincode", event.ChaincodeName, "event", event.EventName, "block", event.BlockNumber, "tx", event.TransactionID)
	return nil
}

func sleepOrDone(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
