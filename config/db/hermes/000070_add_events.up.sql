DROP TYPE IF EXISTS event_status;
CREATE TYPE event_status AS ENUM ('EVENT_STATUS_UNSPECIFIED', 'IDENTITY_CREATED', 'CHALLENGE_SENT', 'CHALLENGE_NOOP', 'CHALLENGE_FAIL', 'ACTIVATE_SUCCESS', 'ACTIVATE_FAIL', 'VERIFY_SUCCESS', 'VERIFY_FAIL', 'IDENTITY_DELETED');

-- events is lightly linked to non-org tables for retention purposes
CREATE TABLE events (
  org_id uuid NOT NULL REFERENCES orgs (id),
  app_id uuid NOT NULL,
  identity_id uuid NOT NULL,
  status event_status NOT NULL,
  error varchar(255) NOT NULL,
  created_at timestamptz NOT NULL,
  trace_id uuid NOT NULL,
  PRIMARY KEY (org_id, identity_id, app_id, created_at)
);

CREATE INDEX events_list_latest_filter_identity_id_app_id_idx ON events (org_id, identity_id, app_id, created_at DESC);
CREATE INDEX events_latest_filter_app_id_idx ON events (org_id, app_id, created_at DESC);
