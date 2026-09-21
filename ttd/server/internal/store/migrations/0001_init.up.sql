-- PQC PDF Sign V1 receiver schema (Rencana V1 §18.1). Applied once on startup.
-- Kept intentionally small; slice-2 adds mfa_credentials, refresh tokens, etc.

CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    label      TEXT NOT NULL DEFAULT '',
    platform   TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS devices_account_idx ON devices(account_id);

CREATE TABLE IF NOT EXISTS enrollments (
    id         TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id),
    account_id TEXT NOT NULL REFERENCES accounts(id),
    csr_pem    BYTEA NOT NULL,
    csr_key_fp TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'submitted',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS enrollments_device_idx ON enrollments(device_id);

CREATE TABLE IF NOT EXISTS certificates (
    id            TEXT PRIMARY KEY,
    enrollment_id TEXT NOT NULL REFERENCES enrollments(id),
    device_id     TEXT NOT NULL REFERENCES devices(id),
    account_id    TEXT NOT NULL REFERENCES accounts(id),
    serial        TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    pem           BYTEA NOT NULL,
    not_before    TIMESTAMPTZ NOT NULL,
    not_after     TIMESTAMPTZ NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    revoked_at    TIMESTAMPTZ,
    rev_reason    TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS certificates_serial_idx ON certificates(serial);
CREATE INDEX IF NOT EXISTS certificates_device_idx ON certificates(device_id);

CREATE TABLE IF NOT EXISTS reservations (
    public_id       TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(id),
    device_id       TEXT NOT NULL REFERENCES devices(id),
    original_sha512 TEXT NOT NULL DEFAULT '',
    file_name       TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'reserved',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS signatures (
    public_id                   TEXT PRIMARY KEY REFERENCES reservations(public_id),
    account_id                  TEXT NOT NULL REFERENCES accounts(id),
    device_id                   TEXT NOT NULL REFERENCES devices(id),
    certificate_id              TEXT NOT NULL DEFAULT '',
    cert_serial                 TEXT NOT NULL DEFAULT '',
    cert_fingerprint            TEXT NOT NULL DEFAULT '',
    algorithm                   TEXT NOT NULL DEFAULT '',
    pdf_profile                 TEXT NOT NULL DEFAULT '',
    original_sha512             TEXT NOT NULL DEFAULT '',
    signed_pdf_sha512           TEXT NOT NULL DEFAULT '',
    client_claimed_signing_time TEXT NOT NULL DEFAULT '',
    server_received_at          TIMESTAMPTZ NOT NULL,
    storage_object_key          TEXT NOT NULL,
    signed_size                 INTEGER NOT NULL DEFAULT 0,
    verification_status         TEXT NOT NULL DEFAULT '',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS signatures_account_idx ON signatures(account_id);

CREATE TABLE IF NOT EXISTS objects (
    key  TEXT PRIMARY KEY,
    data BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id         TEXT PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    type       TEXT NOT NULL,
    account_id TEXT NOT NULL DEFAULT '',
    device_id  TEXT NOT NULL DEFAULT '',
    result     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT ''
);
