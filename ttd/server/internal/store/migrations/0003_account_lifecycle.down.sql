DROP INDEX IF EXISTS certificates_account_idx;
DROP INDEX IF EXISTS accounts_status_idx;
ALTER TABLE accounts DROP COLUMN IF EXISTS status;
ALTER TABLE accounts DROP COLUMN IF EXISTS organization;
ALTER TABLE accounts DROP COLUMN IF EXISTS full_name;
