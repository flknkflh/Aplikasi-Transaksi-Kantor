package httpapi

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// enqueueOutbox inserts one outbox_event row within the caller's DB
// transaction. payload must already be a JSON array of string arguments, in
// the order the named chaincode function expects. created_at uses
// clock_timestamp() (not the transaction-start now()) so rows queued in one DB
// transaction keep their insertion order when the worker sorts by created_at — see
// ledger/api/internal/outbox for the worker that consumes it.
func enqueueOutbox(ctx context.Context, tx pgx.Tx, aggregateType, aggregateID, chaincodeName, fnName string, payload []byte) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO outbox_event (id, aggregate_type, aggregate_id, chaincode_name, fn_name, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp())`,
		uuid.NewString(), aggregateType, aggregateID, chaincodeName, fnName, payload,
	)
	return err
}
