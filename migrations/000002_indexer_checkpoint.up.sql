-- Tracks the indexer's last-processed block per chaincode so it can resume
-- (client.WithStartBlock) after a restart instead of losing its place
-- (PRD FR-009: "Event listener idempotent dan dapat mengejar event setelah
-- downtime").
CREATE TABLE indexer_checkpoint (
    chaincode_name    TEXT PRIMARY KEY,
    last_block_number BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
