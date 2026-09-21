// Package outbox implements the transactional-outbox relay described in
// docs/Hybrid_PQC_Permissioned_Blockchain_PRD.md §5.1 steps 6-7 and §9: the
// API writes its Postgres row and an outbox_event row in one DB transaction,
// and this worker is solely responsible for getting that event onto the
// Fabric ledger — so a crash between the DB commit and the Fabric submit
// can never silently lose an event. It intentionally does not update
// transaction_event/custody_event's fabric_tx_id/committed_at columns; that
// is the indexer's job (it learns about the *actual* commit from a
// chaincode event, which is the only trustworthy source for that).
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ledger/api/internal/fabricclient"
)

type Worker struct {
	db          *pgxpool.Pool
	fabric      *fabricclient.Client
	interval    time.Duration
	maxAttempts int
	logger      *slog.Logger
}

func NewWorker(db *pgxpool.Pool, fabric *fabricclient.Client, interval time.Duration, maxAttempts int, logger *slog.Logger) *Worker {
	return &Worker{db: db, fabric: fabric, interval: interval, maxAttempts: maxAttempts, logger: logger}
}

// Run polls until ctx is cancelled. Each tick processes one batch; batches
// keep running back-to-back while they're full, so a backlog drains quickly
// instead of waiting out the poll interval between every single event.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := w.processBatch(ctx)
				if err != nil {
					w.logger.Error("outbox: process batch", "error", err)
					break
				}
				if n == 0 {
					break
				}
			}
		}
	}
}

const batchSize = 20

type outboxRow struct {
	ID         string
	ChaincodeName string
	FnName     string
	Payload    []byte
	Attempts   int
	AggregateType string
	AggregateID   string
}

// processBatch claims up to batchSize due rows with SKIP LOCKED (safe for
// multiple worker instances), submits each to Fabric, and returns how many
// rows it processed.
func (w *Worker) processBatch(ctx context.Context) (int, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, chaincode_name, fn_name, payload, attempts, aggregate_type, aggregate_id
		FROM outbox_event
		WHERE status = 'pending' AND next_attempt_at <= now()
		ORDER BY created_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, batchSize)
	if err != nil {
		return 0, fmt.Errorf("query pending: %w", err)
	}

	var claimed []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.ID, &r.ChaincodeName, &r.FnName, &r.Payload, &r.Attempts, &r.AggregateType, &r.AggregateID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan: %w", err)
		}
		claimed = append(claimed, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(claimed) == 0 {
		return 0, nil
	}

	// Submitting to Fabric happens outside the DB transaction (it's a
	// network call to a different system); we commit this tx now just to
	// release the row locks, and update each row's outcome in its own
	// follow-up statement.
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit claim: %w", err)
	}

	for _, r := range claimed {
		w.submitOne(ctx, r)
	}
	return len(claimed), nil
}

func (w *Worker) submitOne(ctx context.Context, r outboxRow) {
	var args []string
	if err := json.Unmarshal(r.Payload, &args); err != nil {
		w.markFailed(ctx, r, w.maxAttempts, fmt.Errorf("invalid payload: %w", err)) // not retryable
		return
	}

	contract := w.fabric.Contract(r.ChaincodeName)
	_, err := contract.SubmitTransaction(r.FnName, args...)
	if err != nil {
		w.markFailed(ctx, r, r.Attempts+1, err)
		return
	}

	if _, err := w.db.Exec(ctx, `
		UPDATE outbox_event SET status = 'sent', sent_at = now() WHERE id = $1`, r.ID); err != nil {
		w.logger.Error("outbox: mark sent", "id", r.ID, "error", err)
	}
}

func (w *Worker) markFailed(ctx context.Context, r outboxRow, attempts int, cause error) {
	status := "pending"
	if attempts >= w.maxAttempts {
		status = "dead_letter"
	}
	backoff := time.Duration(math.Min(float64(60*time.Second), float64(time.Second)*math.Pow(2, float64(attempts)))) // capped at 60s

	w.logger.Warn("outbox: submit failed", "id", r.ID, "chaincode", r.ChaincodeName, "fn", r.FnName, "attempts", attempts, "status", status, "error", cause)

	if _, err := w.db.Exec(ctx, `
		UPDATE outbox_event
		SET status = $2, attempts = $3, last_error = $4, next_attempt_at = now() + $5::interval
		WHERE id = $1`,
		r.ID, status, attempts, cause.Error(), backoff.String(),
	); err != nil {
		w.logger.Error("outbox: mark failed", "id", r.ID, "error", err)
	}
}
