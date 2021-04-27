CREATE TABLE orgs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name varchar(40) UNIQUE NOT NULL CHECK (name = lower(name)),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX orgs_paginate_idx ON orgs (created_at, id);

DROP TYPE IF EXISTS role;
CREATE TYPE role AS ENUM ('ROLE_UNSPECIFIED', 'VIEWER', 'AUTHENTICATOR', 'ADMIN', 'SYS_ADMIN');

DROP TYPE IF EXISTS status;
CREATE TYPE status AS ENUM ('STATUS_UNSPECIFIED', 'ACTIVE', 'DISABLED');

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES orgs (id),
  name varchar(80) NOT NULL,
  email varchar(80) NOT NULL,
  password_hash bytea NOT NULL DEFAULT '',
  role role NOT NULL,
  status status NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX users_read_and_email_idx ON users (org_id, email);
CREATE INDEX users_read_and_paginate_idx ON users (org_id, created_at, id);

CREATE TABLE keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES orgs (id),
  name varchar(80) NOT NULL,
  role role NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE INDEX keys_read_and_paginate_idx ON keys (org_id, created_at, id);
