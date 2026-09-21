-- Super-admin login security (docs/adr/0005-superadmin-login.md): TOTP secret (sealed by
-- the application), whether it is enrolled, whether the initial password must be
-- changed, the last accepted TOTP step (replay protection) and the failed-attempt lockout.
CREATE TABLE IF NOT EXISTS superadmin_security (
    account_id     TEXT PRIMARY KEY REFERENCES accounts(id),
    totp_secret    BYTEA NOT NULL DEFAULT ''::bytea,
    totp_enabled   BOOLEAN NOT NULL DEFAULT false,
    must_change    BOOLEAN NOT NULL DEFAULT false,
    last_step      BIGINT NOT NULL DEFAULT 0,
    failed_count   INTEGER NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
