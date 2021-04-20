package app

import (
	"context"
	"fmt"
	"time"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/hlog"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const createApp = `
INSERT INTO apps (org_id, name, digits, subject_template, text_body_template,
html_body_template, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
RETURNING id
`

// Create creates an application in the database.
func (d *DAO) Create(ctx context.Context, app *api.App) (*api.App, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	app.CreatedAt = timestamppb.New(now)
	app.UpdatedAt = timestamppb.New(now)

	if err := d.pg.QueryRowContext(ctx, createApp, app.OrgId, app.Name,
		app.Digits, app.SubjectTemplate, app.TextBodyTemplate,
		app.HtmlBodyTemplate, now).Scan(&app.Id); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	return app, nil
}

const readApp = `
SELECT id, org_id, name, digits, subject_template, text_body_template,
html_body_template, created_at, updated_at
FROM apps
WHERE (id, org_id) = ($1, $2)
`

// Read retrieves an application by ID and org ID.
func (d *DAO) Read(ctx context.Context, appID, orgID string) (*api.App, error) {
	app := &api.App{}
	var createdAt, updatedAt time.Time

	if err := d.pg.QueryRowContext(ctx, readApp, appID, orgID).Scan(&app.Id,
		&app.OrgId, &app.Name, &app.Digits, &app.SubjectTemplate,
		&app.TextBodyTemplate, &app.HtmlBodyTemplate, &createdAt,
		&updatedAt); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	app.CreatedAt = timestamppb.New(createdAt)
	app.UpdatedAt = timestamppb.New(updatedAt)

	return app, nil
}

const updateApp = `
UPDATE apps
SET name = $1, digits = $2, subject_template = $3, text_body_template = $4,
html_body_template = $5, updated_at = $6
WHERE (id, org_id) = ($7, $8)
RETURNING created_at
`

// Update updates an application in the database. CreatedAt should not update,
// so it is safe to override it at the DAO level.
func (d *DAO) Update(ctx context.Context, app *api.App) (*api.App,
	error) {
	var createdAt time.Time
	updatedAt := time.Now().UTC().Truncate(time.Microsecond)
	app.UpdatedAt = timestamppb.New(updatedAt)

	if err := d.pg.QueryRowContext(ctx, updateApp, app.Name, app.Digits,
		app.SubjectTemplate, app.TextBodyTemplate, app.HtmlBodyTemplate,
		updatedAt, app.Id, app.OrgId).Scan(&createdAt); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	app.CreatedAt = timestamppb.New(createdAt)

	return app, nil
}

const deleteApp = `
DELETE FROM apps
WHERE (id, org_id) = ($1, $2)
`

// Delete deletes an application by ID and org ID.
func (d *DAO) Delete(ctx context.Context, appID, orgID string) error {
	// Verify a app exists before attempting to delete it. Do not remap the
	// error.
	if _, err := d.Read(ctx, appID, orgID); err != nil {
		return err
	}

	_, err := d.pg.ExecContext(ctx, deleteApp, appID, orgID)

	return dao.DBToSentinel(err)
}

const countApps = `
SELECT count(*)
FROM apps
WHERE org_id = $1
`

const listApps = `
SELECT id, org_id, name, digits, subject_template, text_body_template,
html_body_template, created_at, updated_at
FROM apps
WHERE org_id = $1
`

const listAppsTSAndID = `
AND (created_at > $2
OR (created_at = $2
AND id > $3
))
`

const listAppsLimit = `
ORDER BY created_at ASC, id ASC
LIMIT %d
`

// List retrieves all applications by org ID with pagination. If lBoundTS and
// prevID are zero values, the first page of results is returned. Limits of 0 or
// less do not apply a limit. List returns a slice of apps, a total count, and
// an error value.
func (d *DAO) List(ctx context.Context, orgID string, lBoundTS time.Time,
	prevID string, limit int32) ([]*api.App, int32, error) {
	// Run count query.
	var count int32
	if err := d.pg.QueryRowContext(ctx, countApps, orgID).Scan(
		&count); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	// Build list query.
	query := listApps
	args := []interface{}{orgID}

	if prevID != "" && !lBoundTS.IsZero() {
		query += listAppsTSAndID
		args = append(args, lBoundTS, prevID)
	}

	// Ordering is applied with the limit, which will always be present for API
	// usage, whereas lBoundTS and prevID will not for first pages.
	if limit > 0 {
		query += fmt.Sprintf(listAppsLimit, limit)
	}

	// Run list query.
	rows, err := d.pg.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}
	defer func() {
		if err = rows.Close(); err != nil {
			logger := hlog.FromContext(ctx)
			logger.Errorf("List rows.Close: %v", err)
		}
	}()

	var apps []*api.App
	for rows.Next() {
		app := &api.App{}
		var createdAt, updatedAt time.Time

		if err = rows.Scan(&app.Id, &app.OrgId, &app.Name, &app.Digits,
			&app.SubjectTemplate, &app.TextBodyTemplate, &app.HtmlBodyTemplate,
			&createdAt, &updatedAt); err != nil {
			return nil, 0, dao.DBToSentinel(err)
		}

		app.CreatedAt = timestamppb.New(createdAt)
		app.UpdatedAt = timestamppb.New(updatedAt)
		apps = append(apps, app)
	}

	if err = rows.Close(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	return apps, count, nil
}
