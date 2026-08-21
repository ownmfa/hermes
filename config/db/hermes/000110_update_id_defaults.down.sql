DROP EXTENSION IF EXISTS pgcrypto;
ALTER TABLE orgs ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE users ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE keys ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE apps ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE identities ALTER COLUMN id SET DEFAULT gen_random_uuid();
