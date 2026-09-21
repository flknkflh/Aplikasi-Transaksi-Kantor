-- Office app (single-app integration of the ledger with TTD, docs/adr/0003).
-- Purely additive: existing Fase 1 columns/tables are untouched.

-- Roles assigned by an admin; accounts are TTD accounts (id = TTD account id).
CREATE TABLE office_role (
    account_id  TEXT PRIMARY KEY,
    role        TEXT NOT NULL CHECK (role IN ('requester', 'approver', 'auditor')),
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE user_identity ADD COLUMN email TEXT;

-- Business fields of an office request (title, category, amount, description).
ALTER TABLE transaction ADD COLUMN office_meta JSONB;

-- The event payload that was hashed+signed, and who acted, so the timeline can
-- be rendered from the read model (the ledger only holds the hash).
ALTER TABLE transaction_event ADD COLUMN payload  JSONB;
ALTER TABLE transaction_event ADD COLUMN actor_id TEXT;

-- Attachments: the original PDF and the TTD-signed PDF.
ALTER TABLE document_reference ADD COLUMN kind        TEXT NOT NULL DEFAULT 'attachment'
    CHECK (kind IN ('attachment', 'signed'));
ALTER TABLE document_reference ADD COLUMN file_name   TEXT;
ALTER TABLE document_reference ADD COLUMN sha512_hash TEXT;
ALTER TABLE document_reference ADD COLUMN size_bytes  BIGINT;

-- One TTD signature can back at most one approval.
CREATE UNIQUE INDEX idx_event_ttd_public_id
    ON transaction_event ((payload->>'ttd_public_id'))
    WHERE payload->>'ttd_public_id' IS NOT NULL;

CREATE INDEX idx_transaction_created_by ON transaction (created_by, created_at DESC);
CREATE INDEX idx_transaction_status ON transaction (status, created_at DESC);
