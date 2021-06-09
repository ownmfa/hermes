package event

import (
	"context"
	"time"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/hlog"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const createEvent = `
INSERT INTO events (org_id, app_id, identity_id, status, error, created_at,
trace_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`

// Create creates an event in the database. Events are retrieved elsewhere in
// bulk, so only an error value is returned.
func (d *DAO) Create(ctx context.Context, event *api.Event) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	event.CreatedAt = timestamppb.New(now)

	_, err := d.pg.ExecContext(ctx, createEvent, event.OrgId, event.AppId,
		event.IdentityId, event.Status.String(), event.Error, now,
		event.TraceId)

	return dao.DBToSentinel(err)
}

const listEvents = `
SELECT org_id, app_id, identity_id, status, error, created_at, trace_id
FROM events
WHERE (org_id, identity_id) = ($1, $2)
AND created_at <= $3
AND created_at > $4
ORDER BY created_at DESC
`

// List retrieves all events by org ID, identity ID, and [end, start) times.
func (d *DAO) List(ctx context.Context, orgID, identityID string, end,
	start time.Time) ([]*api.Event, error) {
	rows, err := d.pg.QueryContext(ctx, listEvents, orgID, identityID, end,
		start)
	if err != nil {
		return nil, dao.DBToSentinel(err)
	}
	defer func() {
		if err = rows.Close(); err != nil {
			logger := hlog.FromContext(ctx)
			logger.Errorf("List rows.Close: %v", err)
		}
	}()

	var events []*api.Event
	for rows.Next() {
		event := &api.Event{}
		var status string
		var createdAt time.Time

		if err = rows.Scan(&event.OrgId, &event.AppId, &event.IdentityId,
			&status, &event.Error, &createdAt, &event.TraceId); err != nil {
			return nil, dao.DBToSentinel(err)
		}

		event.Status = api.EventStatus(api.EventStatus_value[status])
		event.CreatedAt = timestamppb.New(createdAt)
		events = append(events, event)
	}

	if err = rows.Close(); err != nil {
		return nil, dao.DBToSentinel(err)
	}
	if err = rows.Err(); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	return events, nil
}

const latestEvents = `
SELECT
  e.org_id,
  e.app_id,
  e.identity_id,
  e.status,
  e.error,
  e.created_at,
  e.trace_id
FROM
  events e
  INNER JOIN (
    SELECT
      org_id,
      identity_id,
      MAX(created_at) AS created_at
    FROM
      events
    WHERE
      org_id = $1
    GROUP BY
      org_id,
      identity_id
  ) m ON (e.org_id, e.identity_id, e.created_at) = (
    m.org_id, m.identity_id, m.created_at)
`

const latestEventsAppIDIdentityID = `
WHERE e.app_id = $2
AND e.identity_id = $3
`

const latestEventsAppID = `
WHERE e.app_id = $2
`

const latestEventsIdentityID = `
WHERE e.identity_id = $2
`

const latestEventsOrder = `
ORDER BY e.created_at DESC
`

// Latest retrieves the latest events for each of an organization's identity by
// org ID and any of the following: app ID, identity ID.
func (d *DAO) Latest(ctx context.Context, orgID, appID,
	identityID string) ([]*api.Event, error) {
	// Build latest query.
	query := latestEvents
	args := []interface{}{orgID}

	switch {
	case appID != "" && identityID != "":
		query += latestEventsAppIDIdentityID
		args = append(args, appID, identityID)
	case appID != "":
		query += latestEventsAppID
		args = append(args, appID)
	case identityID != "":
		query += latestEventsIdentityID
		args = append(args, identityID)
	}

	query += latestEventsOrder

	// Run latest query.
	rows, err := d.pg.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, dao.DBToSentinel(err)
	}
	defer func() {
		if err = rows.Close(); err != nil {
			logger := hlog.FromContext(ctx)
			logger.Errorf("Latest rows.Close: %v", err)
		}
	}()

	var events []*api.Event
	for rows.Next() {
		event := &api.Event{}
		var status string
		var createdAt time.Time

		if err = rows.Scan(&event.OrgId, &event.AppId, &event.IdentityId,
			&status, &event.Error, &createdAt, &event.TraceId); err != nil {
			return nil, dao.DBToSentinel(err)
		}

		event.Status = api.EventStatus(api.EventStatus_value[status])
		event.CreatedAt = timestamppb.New(createdAt)
		events = append(events, event)
	}

	if err = rows.Close(); err != nil {
		return nil, dao.DBToSentinel(err)
	}
	if err = rows.Err(); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	return events, nil
}
