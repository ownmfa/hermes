DROP TYPE IF EXISTS identity_status;
CREATE TYPE identity_status AS ENUM ('UNVERIFIED', 'ACTIVATED');

DROP TYPE IF EXISTS algorithm;
CREATE TYPE algorithm AS ENUM ('hotp', 'totp');

DROP TYPE IF EXISTS hash;
CREATE TYPE hash AS ENUM ('SHA512', 'SHA256', 'SHA1');

CREATE TABLE identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES orgs (id),
  app_id uuid NOT NULL REFERENCES apps (id),
  comment varchar(80) NOT NULL,
  status identity_status NOT NULL,
  algorithm algorithm NOT NULL,
  hash hash NOT NULL,
  digits integer NOT NULL,
  secret_enc bytea CHECK (octet_length(secret_enc) <= 128),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX identities_read_and_paginate_idx ON identities (org_id, created_at, id);
CREATE INDEX identities_read_and_paginate_filter_app_id_idx ON identities (org_id, app_id, created_at, id);
