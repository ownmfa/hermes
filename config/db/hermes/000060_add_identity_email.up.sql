ALTER TABLE identities ADD COLUMN email varchar(80) NOT NULL DEFAULT '';
ALTER TABLE identities ALTER COLUMN email DROP DEFAULT;
