package org

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/proto/go/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const createOrg = `
INSERT INTO orgs (name, status, plan, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
RETURNING id
`

// Create creates an organization in the database.
func (d *DAO) Create(ctx context.Context, org *api.Org) (*api.Org, error) {
	org.Name = strings.ToLower(org.GetName())
	now := time.Now().UTC().Truncate(time.Microsecond)
	org.CreatedAt = timestamppb.New(now)
	org.UpdatedAt = timestamppb.New(now)

	if err := d.rw.QueryRowContext(ctx, createOrg, org.GetName(),
		org.GetStatus().String(), org.GetPlan().String(),
		now).Scan(&org.Id); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	return org, nil
}

const readOrg = `
SELECT id, name, status, plan, created_at, updated_at
FROM orgs
WHERE id = $1
`

// Read retrieves an organization by ID.
func (d *DAO) Read(ctx context.Context, orgID string) (*api.Org, error) {
	org := &api.Org{}

	if d.cache != nil {
		ok, bOrg, err := d.cache.GetB(ctx, orgKey(orgID))
		if err != nil {
			return nil, dao.DBToSentinel(err)
		}

		if ok {
			if err := proto.Unmarshal(bOrg, org); err != nil {
				return nil, dao.DBToSentinel(err)
			}

			return org, nil
		}
	}

	var status, plan string
	var createdAt, updatedAt time.Time

	if err := d.ro.QueryRowContext(ctx, readOrg, orgID).Scan(&org.Id, &org.Name,
		&status, &plan, &createdAt, &updatedAt); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	org.Status = api.Status(api.Status_value[status])
	org.Plan = api.Plan(api.Plan_value[plan])
	org.CreatedAt = timestamppb.New(createdAt)
	org.UpdatedAt = timestamppb.New(updatedAt)

	// Cache write errors should not prevent successful database reads.
	if d.cache != nil {
		logger := hlog.FromContext(ctx)

		bOrg, err := proto.Marshal(org)
		if err != nil {
			logger.Errorf("Read proto.Marshal: %v", err)

			return org, nil
		}

		if err = d.cache.SetTTL(ctx, orgKey(orgID), bOrg, d.exp); err != nil {
			logger.Errorf("Read d.cache.SetTTL: %v", err)
		}
	}

	return org, nil
}

const updateOrg = `
UPDATE orgs
SET name = $1, status = $2, plan = $3, updated_at = $4
WHERE id = $5
RETURNING created_at
`

// Update updates an organization in the database. CreatedAt should not
// update, so it is safe to override it at the DAO level.
func (d *DAO) Update(ctx context.Context, org *api.Org) (*api.Org, error) {
	org.Name = strings.ToLower(org.GetName())
	var createdAt time.Time
	updatedAt := time.Now().UTC().Truncate(time.Microsecond)
	org.UpdatedAt = timestamppb.New(updatedAt)

	if err := d.rw.QueryRowContext(ctx, updateOrg, org.GetName(),
		org.GetStatus().String(), org.GetPlan().String(), updatedAt,
		org.GetId()).Scan(&createdAt); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	org.CreatedAt = timestamppb.New(createdAt)

	// Invalidate cache on update.
	if d.cache != nil {
		if err := d.cache.Del(ctx, orgKey(org.GetId())); err != nil {
			logger := hlog.FromContext(ctx)
			logger.Errorf("Update d.cache.Del: %v", err)
		}
	}

	return org, nil
}

const deleteOrg = `
DELETE FROM orgs
WHERE id = $1
`

// Delete deletes an organization by ID.
func (d *DAO) Delete(ctx context.Context, orgID string) error {
	// Verify an org exists before attempting to delete it. Do not remap the
	// error.
	if _, err := d.Read(ctx, orgID); err != nil {
		return err
	}

	_, err := d.rw.ExecContext(ctx, deleteOrg, orgID)

	// Invalidate cache on delete.
	if d.cache != nil {
		if err := d.cache.Del(ctx, orgKey(orgID)); err != nil {
			logger := hlog.FromContext(ctx)
			logger.Errorf("Delete d.cache.Del: %v", err)
		}
	}

	return dao.DBToSentinel(err)
}

const countOrgs = `
SELECT count(*)
FROM orgs
`

const listOrgs = `
SELECT id, name, status, plan, created_at, updated_at
FROM orgs
`

const listOrgsTSAndID = `
WHERE (created_at > $1
OR (created_at = $1
AND id > $2
))
`

const listOrgsLimit = `
ORDER BY created_at ASC, id ASC
LIMIT %d
`

// List retrieves all organizations with pagination. If lBoundTS and prevID are
// zero values, the first page of results is returned. Limits of 0 or less do
// not apply a limit. List returns a slice of orgs, a total count, and an error
// value.
func (d *DAO) List(
	ctx context.Context, lBoundTS time.Time, prevID string, limit int32,
) ([]*api.Org, int32, error) {
	// Run count query.
	var count int32
	if err := d.ro.QueryRowContext(ctx, countOrgs).Scan(&count); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	// Build list query.
	query := listOrgs
	args := []interface{}{}

	if prevID != "" && !lBoundTS.IsZero() {
		query += listOrgsTSAndID
		args = append(args, lBoundTS, prevID)
	}

	// Ordering is applied with the limit, which will always be present for API
	// usage, whereas lBoundTS and prevID will not for first pages.
	if limit > 0 {
		query += fmt.Sprintf(listOrgsLimit, limit)
	}

	// Run list query.
	rows, err := d.ro.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}
	defer func() {
		if err = rows.Close(); err != nil {
			logger := hlog.FromContext(ctx)
			logger.Errorf("List rows.Close: %v", err)
		}
	}()

	var orgs []*api.Org
	for rows.Next() {
		org := &api.Org{}
		var status, plan string
		var createdAt, updatedAt time.Time

		if err = rows.Scan(&org.Id, &org.Name, &status, &plan, &createdAt,
			&updatedAt); err != nil {
			return nil, 0, dao.DBToSentinel(err)
		}

		org.Status = api.Status(api.Status_value[status])
		org.Plan = api.Plan(api.Plan_value[plan])
		org.CreatedAt = timestamppb.New(createdAt)
		org.UpdatedAt = timestamppb.New(updatedAt)
		orgs = append(orgs, org)
	}

	if err = rows.Close(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	return orgs, count, nil
}
