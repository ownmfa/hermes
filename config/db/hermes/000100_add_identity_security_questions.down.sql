ALTER TABLE identities DROP COLUMN answer_enc;

ALTER TABLE identities ALTER COLUMN secret_enc SET NULL;
