-- irreversible: MFA support was removed from the code.
CREATE TABLE IF NOT EXISTS mfa_credentials (account_id TEXT PRIMARY KEY, secret TEXT NOT NULL, confirmed BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
