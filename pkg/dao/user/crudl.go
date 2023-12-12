package user

import (
	"context"
	"fmt"
	"time"

	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/proto/go/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const createUser = `
INSERT INTO users (org_id, name, email, role, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $6)
RETURNING id
`

// Create creates a user in the database.
func (d *DAO) Create(ctx context.Context, user *api.User) (*api.User, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	user.CreatedAt = timestamppb.New(now)
	user.UpdatedAt = timestamppb.New(now)

	if err := d.rw.QueryRowContext(ctx, createUser, user.GetOrgId(),
		user.GetName(), user.GetEmail(), user.GetRole().String(),
		user.GetStatus().String(), now).Scan(&user.Id); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	return user, nil
}

const readUser = `
SELECT id, org_id, name, email, role, status, created_at, updated_at
FROM users
WHERE (id, org_id) = ($1, $2)
`

// Read retrieves a user by ID and org ID.
func (d *DAO) Read(ctx context.Context, userID, orgID string) (
	*api.User, error,
) {
	user := &api.User{}
	var role, status string
	var createdAt, updatedAt time.Time

	if err := d.ro.QueryRowContext(ctx, readUser, userID, orgID).Scan(&user.Id,
		&user.OrgId, &user.Name, &user.Email, &role, &status, &createdAt,
		&updatedAt); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	user.Role = api.Role(api.Role_value[role])
	user.Status = api.Status(api.Status_value[status])
	user.CreatedAt = timestamppb.New(createdAt)
	user.UpdatedAt = timestamppb.New(updatedAt)

	return user, nil
}

const readUserByEmail = `
SELECT u.id, u.org_id, u.name, u.email, u.password_hash, u.role, u.status,
u.created_at, u.updated_at
FROM users u
INNER JOIN orgs o ON u.org_id = o.id
WHERE (u.email, u.status, o.name, o.status) = ($1, 'ACTIVE', $2, 'ACTIVE')
`

// ReadByEmail retrieves an active user and password hash by email and active
// org name.
func (d *DAO) ReadByEmail(ctx context.Context, email, orgName string) (
	*api.User, []byte, error,
) {
	user := &api.User{}
	var passHash []byte
	var role, status string
	var createdAt, updatedAt time.Time

	if err := d.ro.QueryRowContext(ctx, readUserByEmail, email, orgName).Scan(
		&user.Id, &user.OrgId, &user.Name, &user.Email, &passHash, &role,
		&status, &createdAt, &updatedAt); err != nil {
		return nil, nil, dao.DBToSentinel(err)
	}

	user.Role = api.Role(api.Role_value[role])
	user.Status = api.Status(api.Status_value[status])
	user.CreatedAt = timestamppb.New(createdAt)
	user.UpdatedAt = timestamppb.New(updatedAt)

	return user, passHash, nil
}

const updateUser = `
UPDATE users
SET name = $1, email = $2, role = $3, status = $4, updated_at = $5
WHERE (id, org_id) = ($6, $7)
RETURNING created_at
`

// Update updates a user in the database. CreatedAt should not update, so it is
// safe to override it at the DAO level.
func (d *DAO) Update(ctx context.Context, user *api.User) (*api.User, error) {
	var createdAt time.Time
	updatedAt := time.Now().UTC().Truncate(time.Microsecond)
	user.UpdatedAt = timestamppb.New(updatedAt)

	if err := d.rw.QueryRowContext(ctx, updateUser, user.GetName(),
		user.GetEmail(), user.GetRole().String(), user.GetStatus().String(),
		updatedAt, user.GetId(), user.GetOrgId()).Scan(&createdAt); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	user.CreatedAt = timestamppb.New(createdAt)

	return user, nil
}

// #nosec G101 // false positive for hardcoded credentials
const updateUserPassword = `
UPDATE users
SET password_hash = $1, updated_at = $2
WHERE (id, org_id) = ($3, $4)
`

// UpdatePassword updates a user's password by ID and org ID.
func (d *DAO) UpdatePassword(
	ctx context.Context, userID, orgID string, passHash []byte,
) error {
	// Verify a user exists before attempting to update it. Do not remap the
	// error.
	if _, err := d.Read(ctx, userID, orgID); err != nil {
		return err
	}

	_, err := d.rw.ExecContext(ctx, updateUserPassword, passHash,
		time.Now().UTC().Truncate(time.Microsecond), userID, orgID)

	return dao.DBToSentinel(err)
}

const deleteUser = `
DELETE FROM users
WHERE (id, org_id) = ($1, $2)
`

// Delete deletes a user by ID and org ID.
func (d *DAO) Delete(ctx context.Context, userID, orgID string) error {
	// Verify a user exists before attempting to delete it. Do not remap the
	// error.
	if _, err := d.Read(ctx, userID, orgID); err != nil {
		return err
	}

	_, err := d.rw.ExecContext(ctx, deleteUser, userID, orgID)

	return dao.DBToSentinel(err)
}

const countUsers = `
SELECT count(*)
FROM users
WHERE org_id = $1
`

const listUsers = `
SELECT id, org_id, name, email, role, status, created_at, updated_at
FROM users
WHERE org_id = $1
`

const listUsersTSAndID = `
AND (created_at > $2
OR (created_at = $2
AND id > $3
))
`

const listUsersLimit = `
ORDER BY created_at ASC, id ASC
LIMIT %d
`

// List retrieves all users by org ID with pagination. If lBoundTS and prevID
// are zero values, the first page of results is returned. Limits of 0 or less
// do not apply a limit. List returns a slice of users, a total count, and an
// error value.
func (d *DAO) List(
	ctx context.Context, orgID string, lBoundTS time.Time, prevID string,
	limit int32,
) ([]*api.User, int32, error) {
	// Run count query.
	var count int32
	if err := d.ro.QueryRowContext(ctx, countUsers, orgID).Scan(
		&count); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	// Build list query.
	query := listUsers
	args := []interface{}{orgID}

	if prevID != "" && !lBoundTS.IsZero() {
		query += listUsersTSAndID
		args = append(args, lBoundTS, prevID)
	}

	// Ordering is applied with the limit, which will always be present for API
	// usage, whereas lBoundTS and prevID will not for first pages.
	if limit > 0 {
		query += fmt.Sprintf(listUsersLimit, limit)
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

	var users []*api.User
	for rows.Next() {
		user := &api.User{}
		var role, status string
		var createdAt, updatedAt time.Time

		if err = rows.Scan(&user.Id, &user.OrgId, &user.Name, &user.Email,
			&role, &status, &createdAt, &updatedAt); err != nil {
			return nil, 0, dao.DBToSentinel(err)
		}

		user.Role = api.Role(api.Role_value[role])
		user.Status = api.Status(api.Status_value[status])
		user.CreatedAt = timestamppb.New(createdAt)
		user.UpdatedAt = timestamppb.New(updatedAt)
		users = append(users, user)
	}

	if err = rows.Close(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	return users, count, nil
}
