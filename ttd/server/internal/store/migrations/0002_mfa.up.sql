-- TOTP multi-factor credentials (Rencana V1 §17 auth/mfa/*, §24). One row per
-- account; `confirmed` flips true only after the account proves a code.
CREATE TABLE IF NOT EXISTS mfa_credentials (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id),
    secret     TEXT NOT NULL,          -- base32, RFC 4648 (no padding)
    confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
