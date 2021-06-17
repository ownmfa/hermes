ALTER TABLE identities ADD COLUMN backup_codes integer NOT NULL DEFAULT 0;
ALTER TABLE identities ALTER COLUMN backup_codes DROP DEFAULT;
