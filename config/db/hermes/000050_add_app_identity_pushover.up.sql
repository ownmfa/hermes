ALTER TABLE apps ADD COLUMN pushover_key varchar(80) NOT NULL DEFAULT '';
ALTER TABLE apps ALTER COLUMN pushover_key DROP DEFAULT;

ALTER TABLE identities ADD COLUMN pushover_key varchar(80) NOT NULL DEFAULT '';
ALTER TABLE identities ALTER COLUMN pushover_key DROP DEFAULT;
