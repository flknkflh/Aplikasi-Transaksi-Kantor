// Package checkpoint tracks the last block number the indexer has processed
// per chaincode, so a restart resumes instead of either replaying the whole
// ledger or silently skipping events (PRD FR-009).
package checkpoint

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Load(ctx context.Context, db *pgxpool.Pool, chaincodeName string) (uint64, error) {
	var last int64
	err := db.QueryRow(ctx, `SELECT last_block_number FROM indexer_checkpoint WHERE chaincode_name = $1`, chaincodeName).Scan(&last)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("checkpoint: load %s: %w", chaincodeName, err)
	}
	return uint64(last), nil
}

// Save upserts the checkpoint, only ever moving it forward — a late-arriving
// lower block number (shouldn't normally happen, since Fabric delivers
// events in order, but defensively) never regresses the checkpoint.
func Save(ctx context.Context, db *pgxpool.Pool, chaincodeName string, blockNumber uint64) error {
	_, err := db.Exec(ctx, `
		INSERT INTO indexer_checkpoint (chaincode_name, last_block_number, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (chaincode_name) DO UPDATE
		SET last_block_number = GREATEST(indexer_checkpoint.last_block_number, EXCLUDED.last_block_number),
		    updated_at = now()`,
		chaincodeName, int64(blockNumber),
	)
	if err != nil {
		return fmt.Errorf("checkpoint: save %s: %w", chaincodeName, err)
	}
	return nil
}
