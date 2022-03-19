package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/pkg/crypto"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/oath"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const createIdentity = `
INSERT INTO identities (org_id, app_id, comment, status, algorithm, hash,
digits, secret_enc, phone, pushover_key, email, backup_codes, answer_enc,
created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
RETURNING id
`

// Create creates an identity in the database. It returns an Identity, OTP, and
// bool representing whether the OTP secret and QR should be returned.
func (d *DAO) Create(ctx context.Context, identity *api.Identity) (
	*api.Identity, *oath.OTP, bool, error,
) {
	// Backup codes and security questions methods do not require activation.
	switch identity.MethodOneof.(type) {
	case *api.Identity_BackupCodesMethod, *api.Identity_SecurityQuestionsMethod:
		identity.Status = api.IdentityStatus_ACTIVATED
	default:
		identity.Status = api.IdentityStatus_UNVERIFIED
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	identity.CreatedAt = timestamppb.New(now)
	identity.UpdatedAt = timestamppb.New(now)

	otp, meta, err := methodToOTP(identity)
	if err != nil {
		return nil, nil, false, dao.DBToSentinel(err)
	}

	secretEnc, err := crypto.Encrypt(d.secretKey, otp.Key)
	if err != nil {
		return nil, nil, false, dao.DBToSentinel(err)
	}

	answerEnc := []byte{}
	if otp.Answer != "" {
		answerEnc, err = crypto.Encrypt(d.secretKey, []byte(otp.Answer))
		if err != nil {
			return nil, nil, false, dao.DBToSentinel(err)
		}
	}

	if err := d.pg.QueryRowContext(ctx, createIdentity, identity.OrgId,
		identity.AppId, identity.Comment, identity.Status.String(),
		otp.Algorithm, hashCryptoToAPI[otp.Hash].String(), otp.Digits,
		secretEnc, meta.phone, meta.pushoverKey, meta.email, meta.backupCodes,
		answerEnc, now).Scan(&identity.Id); err != nil {
		return nil, nil, false, dao.DBToSentinel(err)
	}

	return identity, otp, meta.retSecret, nil
}

const readIdentity = `
SELECT id, org_id, app_id, comment, status, algorithm, hash, digits, secret_enc,
phone, pushover_key, email, backup_codes, answer_enc, created_at, updated_at
FROM identities
WHERE (id, org_id, app_id) = ($1, $2, $3)
`

// Read retrieves an identity by ID, org ID, and app ID. Identity MethodOneof
// may be returned in simplified form.
func (d *DAO) Read(ctx context.Context, identityID, orgID, appID string) (
	*api.Identity, *oath.OTP, error,
) {
	identity := &api.Identity{}
	otp := &oath.OTP{}
	meta := &otpMeta{}
	var status, hash string
	var secretEnc, answerEnc []byte
	var createdAt, updatedAt time.Time

	if err := d.pg.QueryRowContext(ctx, readIdentity, identityID, orgID,
		appID).Scan(&identity.Id, &identity.OrgId, &identity.AppId,
		&identity.Comment, &status, &otp.Algorithm, &hash, &otp.Digits,
		&secretEnc, &meta.phone, &meta.pushoverKey, &meta.email,
		&meta.backupCodes, &answerEnc, &createdAt, &updatedAt); err != nil {
		return nil, nil, dao.DBToSentinel(err)
	}

	if len(answerEnc) > 0 {
		answer, err := crypto.Decrypt(d.secretKey, answerEnc)
		if err != nil {
			return nil, nil, dao.DBToSentinel(err)
		}
		otp.Answer = string(answer)
	}

	otp.Hash = hashAPIToCrypto[api.Hash(api.Hash_value[hash])]
	otpToMethod(identity, otp, meta)
	identity.Status = api.IdentityStatus(api.IdentityStatus_value[status])
	identity.CreatedAt = timestamppb.New(createdAt)
	identity.UpdatedAt = timestamppb.New(updatedAt)

	secret, err := crypto.Decrypt(d.secretKey, secretEnc)
	if err != nil {
		return nil, nil, dao.DBToSentinel(err)
	}
	otp.Key = secret

	return identity, otp, nil
}

const updateIdentityStatus = `
UPDATE identities
SET status = $1, updated_at = $2
WHERE (id, org_id, app_id) = ($3, $4, $5)
`

// UpdateStatus updates an identity's status by ID, org ID, and app ID.
func (d *DAO) UpdateStatus(
	ctx context.Context, identityID, orgID, appID string,
	status api.IdentityStatus,
) (*api.Identity, error) {
	// Read the identity before attempting to update it. Do not remap the error.
	identity, _, err := d.Read(ctx, identityID, orgID, appID)
	if err != nil {
		return nil, err
	}

	identity.Status = status
	updatedAt := time.Now().UTC().Truncate(time.Microsecond)
	identity.UpdatedAt = timestamppb.New(updatedAt)

	if _, err = d.pg.ExecContext(ctx, updateIdentityStatus, status.String(),
		updatedAt, identityID, orgID, appID); err != nil {
		return nil, dao.DBToSentinel(err)
	}

	return identity, nil
}

const deleteIdentity = `
DELETE FROM identities
WHERE (id, org_id, app_id) = ($1, $2, $3)
`

// Delete deletes an identity by ID, org ID, and app ID.
func (d *DAO) Delete(
	ctx context.Context, identityID, orgID, appID string,
) error {
	// Verify an identity exists before attempting to delete it. Do not remap
	// the error.
	if _, _, err := d.Read(ctx, identityID, orgID, appID); err != nil {
		return err
	}

	_, err := d.pg.ExecContext(ctx, deleteIdentity, identityID, orgID, appID)

	return dao.DBToSentinel(err)
}

const countIdentities = `
SELECT count(*)
FROM identities
WHERE org_id = $1
`

const countIdentitiesApp = `
AND app_id = $2
`

const listIdentities = `
SELECT id, org_id, app_id, comment, status, algorithm, hash, digits, phone,
pushover_key, email, backup_codes, answer_enc, created_at, updated_at
FROM identities
WHERE org_id = $1
`

const listIdentitiesTSAndID = `
AND (created_at > $%d
OR (created_at = $%d
AND id > $%d
))
`

const listIdentitiesApp = `
AND app_id = $%d
`

const listIdentitiesLimit = `
ORDER BY created_at ASC, id ASC
LIMIT %d
`

// List retrieves all identities by org ID with pagination and optional app
// filter. If lBoundTS and prevID are zero values, the first page of results is
// returned. Limits of 0 or less do not apply a limit. List returns a slice of
// identities, a total count, and an error value.
func (d *DAO) List(
	ctx context.Context, orgID string, lBoundTS time.Time, prevID string,
	limit int32, appID string,
) ([]*api.Identity, int32, error) {
	// Build count query.
	cQuery := countIdentities
	cArgs := []interface{}{orgID}

	if appID != "" {
		cQuery += countIdentitiesApp
		cArgs = append(cArgs, appID)
	}

	// Run count query.
	var count int32
	if err := d.pg.QueryRowContext(ctx, cQuery, cArgs...).Scan(
		&count); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	// Build list query.
	lQuery := listIdentities
	lArgs := []interface{}{orgID}

	if prevID != "" && !lBoundTS.IsZero() {
		lQuery += fmt.Sprintf(listIdentitiesTSAndID, 2, 2, 3)
		lArgs = append(lArgs, lBoundTS, prevID)

		if appID != "" {
			lQuery += fmt.Sprintf(listIdentitiesApp, 4)
			lArgs = append(lArgs, appID)
		}
	} else if appID != "" {
		lQuery += fmt.Sprintf(listIdentitiesApp, 2)
		lArgs = append(lArgs, appID)
	}

	// Ordering is applied with the limit, which will always be present for API
	// usage, whereas lBoundTS and prevID will not for first pages.
	if limit > 0 {
		lQuery += fmt.Sprintf(listIdentitiesLimit, limit)
	}

	// Run list query.
	rows, err := d.pg.QueryContext(ctx, lQuery, lArgs...)
	if err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}
	defer func() {
		if err = rows.Close(); err != nil {
			logger := hlog.FromContext(ctx)
			logger.Errorf("List rows.Close: %v", err)
		}
	}()

	var identities []*api.Identity
	for rows.Next() {
		identity := &api.Identity{}
		otp := &oath.OTP{}
		meta := &otpMeta{}
		var status, hash string
		var answerEnc []byte
		var createdAt, updatedAt time.Time

		if err = rows.Scan(&identity.Id, &identity.OrgId, &identity.AppId,
			&identity.Comment, &status, &otp.Algorithm, &hash, &otp.Digits,
			&meta.phone, &meta.pushoverKey, &meta.email, &meta.backupCodes,
			&answerEnc, &createdAt, &updatedAt); err != nil {
			return nil, 0, dao.DBToSentinel(err)
		}

		if len(answerEnc) > 0 {
			answer, err := crypto.Decrypt(d.secretKey, answerEnc)
			if err != nil {
				return nil, 0, dao.DBToSentinel(err)
			}
			otp.Answer = string(answer)
		}

		otp.Hash = hashAPIToCrypto[api.Hash(api.Hash_value[hash])]
		otpToMethod(identity, otp, meta)
		identity.Status = api.IdentityStatus(api.IdentityStatus_value[status])
		identity.CreatedAt = timestamppb.New(createdAt)
		identity.UpdatedAt = timestamppb.New(updatedAt)
		identities = append(identities, identity)
	}

	if err = rows.Close(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, dao.DBToSentinel(err)
	}

	return identities, count, nil
}
