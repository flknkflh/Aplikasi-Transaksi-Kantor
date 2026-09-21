DROP INDEX IF EXISTS idx_transaction_status;
DROP INDEX IF EXISTS idx_transaction_created_by;
DROP INDEX IF EXISTS idx_event_ttd_public_id;
ALTER TABLE document_reference DROP COLUMN IF EXISTS size_bytes, DROP COLUMN IF EXISTS sha512_hash,
    DROP COLUMN IF EXISTS file_name, DROP COLUMN IF EXISTS kind;
ALTER TABLE transaction_event DROP COLUMN IF EXISTS actor_id, DROP COLUMN IF EXISTS payload;
ALTER TABLE transaction DROP COLUMN IF EXISTS office_meta;
ALTER TABLE user_identity DROP COLUMN IF EXISTS email;
DROP TABLE IF EXISTS office_role;
