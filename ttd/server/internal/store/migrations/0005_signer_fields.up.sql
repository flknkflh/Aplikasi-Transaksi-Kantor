-- Multi-QR caption change: the e-signature stamp now draws a caption block
-- with the signer's fixed identity (jabatan / NIP) taken from the verified
-- account record. "Dikeluarkan di <kota>" is NOT stored here — it is chosen
-- per signature and passed to /stamp alongside `reason`.
-- Existing rows default to empty strings, so lines with no value are skipped.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS position TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS nip      TEXT NOT NULL DEFAULT '';
