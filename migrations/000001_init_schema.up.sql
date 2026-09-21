-- Fase 1 spike schema. Subset of PRD §7 entities needed to prove the core
-- mechanics (hybrid signing, append-only event chain, idempotency, outbox,
-- audit checkpoints). role_assignment, certificate_metadata, security_event,
-- policy_definition are deferred to Fase 2 (see docs/adr/0001-fase1-spike-scope.md).

CREATE TABLE organization (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    msp_id          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_identity (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization(id),
    display_name    TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN (
                        'requester', 'verifier', 'approver',
                        'warehouse_operator', 'vendor', 'auditor',
                        'app_admin', 'node_operator', 'security_operator', 'data_owner'
                    )),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- key_reference never stores private key material (PRD §7: "Private key hanya
-- direferensikan melalui key_id"). public_key is safe to store; private keys
-- live only in the dev keystore file (crypto/, api/ keystore).
CREATE TABLE key_reference (
    id              TEXT PRIMARY KEY,
    owner_user_id   TEXT NOT NULL REFERENCES user_identity(id),
    key_kind        TEXT NOT NULL CHECK (key_kind IN ('classical', 'pqc')),
    algorithm       TEXT NOT NULL,
    public_key      BYTEA NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);

CREATE TABLE revocation_record (
    id              TEXT PRIMARY KEY,
    key_id          TEXT NOT NULL REFERENCES key_reference(id),
    reason          TEXT NOT NULL,
    revoked_by      TEXT NOT NULL REFERENCES user_identity(id),
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE transaction (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization(id),
    workflow_type   TEXT NOT NULL,
    schema_version  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN (
                        'DRAFT', 'VERIFIED', 'ENDORSED', 'COMMITTED', 'SETTLED',
                        'REJECTED', 'CANCELLED', 'SUPERSEDED', 'REVOKED'
                    )),
    created_by      TEXT NOT NULL REFERENCES user_identity(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Read model of the ledger's append-only event chain. idempotency_key is
-- unique per PRD §7 ("Event yang sama tidak boleh dapat di-commit dua kali").
CREATE TABLE transaction_event (
    id                      TEXT PRIMARY KEY,
    transaction_id          TEXT NOT NULL REFERENCES transaction(id),
    event_sequence          INTEGER NOT NULL,
    event_type              TEXT NOT NULL,
    payload_hash            TEXT NOT NULL,
    previous_event_hash     TEXT,
    algorithm_suite         TEXT NOT NULL,
    classical_key_id        TEXT NOT NULL REFERENCES key_reference(id),
    pqc_key_id              TEXT NOT NULL REFERENCES key_reference(id),
    classical_signature     BYTEA NOT NULL,
    pqc_signature           BYTEA NOT NULL,
    idempotency_key         TEXT NOT NULL UNIQUE,
    created_at_server       TIMESTAMPTZ NOT NULL,
    fabric_tx_id            TEXT,
    fabric_block_number     BIGINT,
    committed_at            TIMESTAMPTZ,
    UNIQUE (transaction_id, event_sequence)
);

CREATE TABLE approval (
    id              TEXT PRIMARY KEY,
    transaction_id  TEXT NOT NULL REFERENCES transaction(id),
    event_id        TEXT NOT NULL REFERENCES transaction_event(id),
    approver_id     TEXT NOT NULL REFERENCES user_identity(id),
    decision        TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    policy_version  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE asset (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization(id),
    asset_tag       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'CREATED' CHECK (status IN (
                        'CREATED', 'RECEIVED', 'INSPECTED', 'STORED', 'ISSUED',
                        'TRANSFERRED', 'MAINTENANCE', 'RETURNED', 'RETIRED'
                    )),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE custody_event (
    id                      TEXT PRIMARY KEY,
    asset_id                TEXT NOT NULL REFERENCES asset(id),
    event_sequence          INTEGER NOT NULL,
    from_party              TEXT,
    to_party                TEXT NOT NULL,
    location_zone           TEXT,
    condition_note          TEXT,
    inspection_result       TEXT,
    payload_hash            TEXT NOT NULL,
    previous_event_hash     TEXT,
    algorithm_suite         TEXT NOT NULL,
    classical_key_id        TEXT NOT NULL REFERENCES key_reference(id),
    pqc_key_id              TEXT NOT NULL REFERENCES key_reference(id),
    classical_signature     BYTEA NOT NULL,
    pqc_signature           BYTEA NOT NULL,
    idempotency_key         TEXT NOT NULL UNIQUE,
    created_at_server       TIMESTAMPTZ NOT NULL,
    fabric_tx_id            TEXT,
    fabric_block_number     BIGINT,
    committed_at            TIMESTAMPTZ,
    UNIQUE (asset_id, event_sequence)
);

-- Documents live off-chain (MinIO in this spike); only the hash is what the
-- ledger event actually commits to (PRD §6 on-chain/off-chain split).
CREATE TABLE document_reference (
    id              TEXT PRIMARY KEY,
    owner_type      TEXT NOT NULL CHECK (owner_type IN ('transaction_event', 'custody_event')),
    owner_id        TEXT NOT NULL,
    storage_bucket  TEXT NOT NULL,
    storage_key     TEXT NOT NULL,
    sha256_hash     TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    uploaded_by     TEXT NOT NULL REFERENCES user_identity(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Transactional outbox (PRD §5.1 step 6-7 / §9): DB write + outbox row commit
-- together; a worker relays to the Fabric Gateway and updates status.
-- payload is a JSON array of string arguments, in the exact order the named
-- chaincode function expects (e.g. ["txn-1","org-a",...] for CreateTransaction,
-- or ["<event JSON>"] for RecordEvent) — this keeps the worker generic across
-- every chaincode function instead of special-casing each one.
CREATE TABLE outbox_event (
    id              TEXT PRIMARY KEY,
    aggregate_type  TEXT NOT NULL CHECK (aggregate_type IN ('transaction', 'asset')),
    aggregate_id    TEXT NOT NULL,
    chaincode_name  TEXT NOT NULL,
    fn_name         TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
                        'pending', 'sent', 'failed', 'dead_letter'
                    )),
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ
);

CREATE INDEX idx_outbox_event_status ON outbox_event (status, next_attempt_at);

-- Independent checkpoints written by the audit-service (PRD §6, §15).
CREATE TABLE audit_checkpoint (
    id              TEXT PRIMARY KEY,
    block_number    BIGINT NOT NULL,
    block_hash      TEXT NOT NULL,
    tx_count        INTEGER NOT NULL,
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
