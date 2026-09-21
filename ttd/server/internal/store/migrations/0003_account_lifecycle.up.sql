-- Rencana RB-1: self-registration + one-click admin approval.
-- Existing rows are pre-approved so a running deployment is not locked out.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS full_name    TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS organization TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'active';

CREATE INDEX IF NOT EXISTS accounts_status_idx ON accounts(status);
CREATE INDEX IF NOT EXISTS certificates_account_idx ON certificates(account_id);
