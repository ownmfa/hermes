CREATE TABLE apps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES orgs (id),
  name varchar(40) NOT NULL,
  digits integer NOT NULL,
  subject_template varchar(1024) NOT NULL,
  text_body_template varchar(4096) NOT NULL,
  html_body_template bytea CHECK (octet_length(html_body_template) <= 4096),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX apps_read_and_paginate_idx ON apps (org_id, created_at, id);
