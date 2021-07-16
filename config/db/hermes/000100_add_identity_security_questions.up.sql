ALTER TABLE identities ALTER COLUMN secret_enc SET NOT NULL;

ALTER TABLE identities ADD COLUMN answer_enc bytea NOT NULL CHECK (octet_length(answer_enc) <= 255) DEFAULT '';
ALTER TABLE identities ALTER COLUMN answer_enc DROP DEFAULT;
