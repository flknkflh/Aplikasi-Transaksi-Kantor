// Package apply updates the Postgres read model from committed chaincode
// events. It only ever matches rows by idempotency_key — the same key the
// API already wrote when it queued the event — so applying the same event
// twice (e.g. after the indexer restarts and replays from its last
// checkpoint) is a no-op the second time, satisfying PRD FR-009's
// idempotency requirement.
package apply

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type eventWithIdempotencyKey struct {
	IdempotencyKey string `json:"idempotency_key"`
}

// TransactionEventRecorded marks the matching transaction_event row as
// committed, with the block/transaction identifiers that prove it — this is
// the only trustworthy source for those columns (PRD §6: the ledger, not the
// API, is what actually committed the event).
func TransactionEventRecorded(ctx context.Context, db *pgxpool.Pool, blockNumber uint64, fabricTxID string, payload []byte) error {
	var evt eventWithIdempotencyKey
	if err := json.Unmarshal(payload, &evt); err != nil {
		return fmt.Errorf("apply: unmarshal TransactionEventRecorded payload: %w", err)
	}
	_, err := db.Exec(ctx, `
		UPDATE transaction_event
		SET fabric_tx_id = $1, fabric_block_number = $2, committed_at = now()
		WHERE idempotency_key = $3`,
		fabricTxID, int64(blockNumber), evt.IdempotencyKey,
	)
	if err != nil {
		return fmt.Errorf("apply: update transaction_event: %w", err)
	}
	return nil
}

// CustodyEventRecorded is the asset-custody twin of TransactionEventRecorded.
func CustodyEventRecorded(ctx context.Context, db *pgxpool.Pool, blockNumber uint64, fabricTxID string, payload []byte) error {
	var evt eventWithIdempotencyKey
	if err := json.Unmarshal(payload, &evt); err != nil {
		return fmt.Errorf("apply: unmarshal CustodyEventRecorded payload: %w", err)
	}
	_, err := db.Exec(ctx, `
		UPDATE custody_event
		SET fabric_tx_id = $1, fabric_block_number = $2, committed_at = now()
		WHERE idempotency_key = $3`,
		fabricTxID, int64(blockNumber), evt.IdempotencyKey,
	)
	if err != nil {
		return fmt.Errorf("apply: update custody_event: %w", err)
	}
	return nil
}
