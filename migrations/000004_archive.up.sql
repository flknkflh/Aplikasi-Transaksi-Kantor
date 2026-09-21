-- Archive app: offices (kantor) share one database; every upload is a signed,
-- ledger-anchored transaction (docs/adr/0004-archive-server-side-signing.md).
-- Purely additive. An office is a row of the existing `organization` table.

-- Which office an account belongs to (assigned by the central admin).
CREATE TABLE office_member (
    account_id      TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization(id),
    assigned_by     TEXT,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_office_member_org ON office_member (organization_id);

-- In-progress resumable uploads (the bytes live in a temp file until completion).
CREATE TABLE archive_upload (
    id              TEXT PRIMARY KEY,
    sender_id       TEXT NOT NULL REFERENCES user_identity(id),
    organization_id TEXT NOT NULL REFERENCES organization(id),
    file_name       TEXT NOT NULL,
    media_type      TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL CHECK (size_bytes >= 0),
    description     TEXT NOT NULL DEFAULT '',
    received_bytes  BIGINT NOT NULL DEFAULT 0,
    temp_path       TEXT NOT NULL,
    client_ip       TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed', 'aborted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_archive_upload_sender ON archive_upload (sender_id, status);

-- One archived submission. The signed manifest and the receipt are kept verbatim.
CREATE TABLE archive_item (
    id              TEXT PRIMARY KEY,
    receipt_id      TEXT NOT NULL UNIQUE,
    transaction_id  TEXT NOT NULL UNIQUE REFERENCES transaction(id),
    organization_id TEXT NOT NULL REFERENCES organization(id),
    sender_id       TEXT NOT NULL REFERENCES user_identity(id),
    file_name       TEXT NOT NULL,
    media_type      TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    sha256          TEXT NOT NULL,
    sha512          TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    storage_key     TEXT NOT NULL,
    client_ip       TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    manifest        JSONB NOT NULL,
    manifest_hash   TEXT NOT NULL,
    receipt         JSONB NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_archive_item_received ON archive_item (received_at DESC);
CREATE INDEX idx_archive_item_org ON archive_item (organization_id, received_at DESC);
CREATE INDEX idx_archive_item_sender ON archive_item (sender_id, received_at DESC);
CREATE INDEX idx_archive_item_sha256 ON archive_item (sha256);

-- Who (admin) looked at or downloaded what: the archive's own access trail.
CREATE TABLE archive_access (
    id         BIGSERIAL PRIMARY KEY,
    item_id    TEXT NOT NULL REFERENCES archive_item(id),
    admin_id   TEXT NOT NULL,
    action     TEXT NOT NULL CHECK (action IN ('view', 'download', 'verify')),
    client_ip  TEXT NOT NULL DEFAULT '',
    at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_archive_access_item ON archive_access (item_id, at DESC);

-- One-time, short-lived download links so an admin's browser can stream a
-- multi-gigabyte file natively (no token in the URL that outlives two minutes).
CREATE TABLE archive_ticket (
    token_hash TEXT PRIMARY KEY,
    item_id    TEXT NOT NULL REFERENCES archive_item(id),
    admin_id   TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);
