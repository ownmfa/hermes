package service

//go:generate mockgen -source app_identity.go -destination mock_apper_test.go -package service

import (
	"context"
	"time"

	"github.com/mennanov/fmutils"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/api/go/common"
	"github.com/ownmfa/hermes/internal/hermes-api/key"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/oath"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Apper defines the methods provided by an app.DAO.
type Apper interface {
	Create(ctx context.Context, app *api.App) (*api.App, error)
	Read(ctx context.Context, appID, orgID string) (*api.App, error)
	Update(ctx context.Context, app *api.App) (*api.App, error)
	Delete(ctx context.Context, appID, orgID string) error
	List(ctx context.Context, orgID string, lBoundTS time.Time, prevID string,
		limit int32) ([]*api.App, int32, error)
}

// Identityer defines the methods provided by an identity.DAO.
type Identityer interface {
	Create(ctx context.Context, identity *api.Identity) (*api.Identity,
		*oath.OTP, bool, error)
	Read(ctx context.Context, identityID, orgID, appID string) (*api.Identity,
		*oath.OTP, error)
	UpdateStatus(ctx context.Context, identityID, orgID, appID string,
		status api.IdentityStatus) (*api.Identity, error)
	Delete(ctx context.Context, identityID, orgID, appID string) error
	List(ctx context.Context, orgID string, lBoundTS time.Time, prevID string,
		limit int32, appID string) ([]*api.Identity, int32, error)
}

// AppIdentity service contains functions to query and modify applications and
// identities.
type AppIdentity struct {
	api.UnimplementedAppIdentityServiceServer

	appDAO      Apper
	identityDAO Identityer
	cache       cache.Cacher
}

// NewAppIdentity instantiates and returns a new AppIdentity service.
func NewAppIdentity(appDAO Apper, identityDAO Identityer,
	cache cache.Cacher) *AppIdentity {
	return &AppIdentity{
		appDAO:      appDAO,
		identityDAO: identityDAO,
		cache:       cache,
	}
}

// CreateApp creates an application.
func (ai *AppIdentity) CreateApp(ctx context.Context,
	req *api.CreateAppRequest) (*api.App, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_ADMIN {
		return nil, errPerm(common.Role_ADMIN)
	}

	req.App.OrgId = sess.OrgID

	app, err := ai.appDAO.Create(ctx, req.App)
	if err != nil {
		return nil, errToStatus(err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		"201")); err != nil {
		logger.Errorf("CreateApp grpc.SetHeader: %v", err)
	}

	return app, nil
}

// CreateIdentity creates an identity.
func (ai *AppIdentity) CreateIdentity(ctx context.Context,
	req *api.CreateIdentityRequest) (*api.CreateIdentityResponse, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_AUTHENTICATOR {
		return nil, errPerm(common.Role_AUTHENTICATOR)
	}

	req.Identity.OrgId = sess.OrgID

	identity, otp, retSecret, err := ai.identityDAO.Create(ctx, req.Identity)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &api.CreateIdentityResponse{Identity: identity}
	if retSecret {
		resp.Secret = otp.Secret()

		app, err := ai.appDAO.Read(ctx, req.Identity.AppId, sess.OrgID)
		if err != nil {
			return nil, errToStatus(err)
		}

		resp.Qr, err = otp.QR(app.DisplayName)
		if err != nil {
			return nil, errToStatus(err)
		}
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		"201")); err != nil {
		logger.Errorf("CreateIdentity grpc.SetHeader: %v", err)
	}

	return resp, nil
}

// ActivateIdentity activates an identity by ID.
func (ai *AppIdentity) ActivateIdentity(ctx context.Context,
	req *api.ActivateIdentityRequest) (*api.Identity, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_AUTHENTICATOR {
		return nil, errPerm(common.Role_AUTHENTICATOR)
	}

	identity, otp, err := ai.identityDAO.Read(ctx, req.Id, sess.OrgID,
		req.AppId)
	if err != nil {
		return nil, errToStatus(err)
	}

	if identity.Status != api.IdentityStatus_UNVERIFIED {
		return nil, status.Error(codes.FailedPrecondition,
			"identity is already activated")
	}

	// Verify initial passcode and calculate HOTP counter or TOTP window offset.
	var counter int64
	var offset int

	switch identity.MethodOneof.(type) {
	case *api.Identity_SoftwareHotpMethod, *api.Identity_GoogleAuthHotpMethod,
		*api.Identity_HardwareHotpMethod:
		counter, err = otp.VerifyHOTP(1000, 0, req.Passcode)
	case *api.Identity_SoftwareTotpMethod, *api.Identity_GoogleAuthTotpMethod,
		*api.Identity_MicrosoftAuthTotpMethod:
		offset, err = otp.VerifyTOTP(6, req.Passcode)
	case *api.Identity_HardwareTotpMethod:
		offset, err = otp.VerifyTOTP(20, req.Passcode)
	}
	if err != nil {
		return nil, errToStatus(err)
	}

	// Add logging fields.
	logger := hlog.FromContext(ctx)
	logger.Logger = logger.WithStr("appID", identity.AppId)
	logger.Logger = logger.WithStr("identityID", identity.Id)
	logger.Infof("ActivateIdentity counter, offset: %v, %v", counter, offset)

	// Save HOTP counter or TOTP window offset for future verifications.
	switch {
	case counter != 0:
		if err = ai.cache.Set(ctx, key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id), counter); err != nil {
			return nil, errToStatus(err)
		}
	case offset != 0:
		if err = ai.cache.Set(ctx, key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id), offset); err != nil {
			return nil, errToStatus(err)
		}
	}

	identity, err = ai.identityDAO.UpdateStatus(ctx, identity.Id,
		identity.OrgId, identity.AppId, api.IdentityStatus_ACTIVATED)
	if err != nil {
		return nil, errToStatus(err)
	}

	return identity, nil
}

// GetApp retrieves an application by ID.
func (ai *AppIdentity) GetApp(ctx context.Context,
	req *api.GetAppRequest) (*api.App, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_VIEWER {
		return nil, errPerm(common.Role_VIEWER)
	}

	app, err := ai.appDAO.Read(ctx, req.Id, sess.OrgID)
	if err != nil {
		return nil, errToStatus(err)
	}

	return app, nil
}

// GetIdentity retrieves an identity by ID.
func (ai *AppIdentity) GetIdentity(ctx context.Context,
	req *api.GetIdentityRequest) (*api.Identity, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_VIEWER {
		return nil, errPerm(common.Role_VIEWER)
	}

	identity, _, err := ai.identityDAO.Read(ctx, req.Id, sess.OrgID, req.AppId)
	if err != nil {
		return nil, errToStatus(err)
	}

	return identity, nil
}

// UpdateApp updates an application. Update actions validate after merge to
// support partial updates.
func (ai *AppIdentity) UpdateApp(ctx context.Context,
	req *api.UpdateAppRequest) (*api.App, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_ADMIN {
		return nil, errPerm(common.Role_ADMIN)
	}

	if req.App == nil {
		return nil, status.Error(codes.InvalidArgument,
			req.Validate().Error())
	}
	req.App.OrgId = sess.OrgID

	// Perform partial update if directed.
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		// Normalize and validate field mask.
		req.UpdateMask.Normalize()
		if !req.UpdateMask.IsValid(req.App) {
			return nil, status.Error(codes.InvalidArgument,
				"invalid field mask")
		}

		app, err := ai.appDAO.Read(ctx, req.App.Id, sess.OrgID)
		if err != nil {
			return nil, errToStatus(err)
		}

		fmutils.Filter(req.App, req.UpdateMask.Paths)
		proto.Merge(app, req.App)
		req.App = app
	}

	// Validate after merge to support partial updates.
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	app, err := ai.appDAO.Update(ctx, req.App)
	if err != nil {
		return nil, errToStatus(err)
	}

	return app, nil
}

// DeleteApp deletes an application by ID.
func (ai *AppIdentity) DeleteApp(ctx context.Context,
	req *api.DeleteAppRequest) (*emptypb.Empty, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_ADMIN {
		return nil, errPerm(common.Role_ADMIN)
	}

	if err := ai.appDAO.Delete(ctx, req.Id, sess.OrgID); err != nil {
		return nil, errToStatus(err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		"204")); err != nil {
		logger.Errorf("DeleteApp grpc.SetHeader: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// DeleteIdentity deletes an identity by ID.
func (ai *AppIdentity) DeleteIdentity(ctx context.Context,
	req *api.DeleteIdentityRequest) (*emptypb.Empty, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_AUTHENTICATOR {
		return nil, errPerm(common.Role_AUTHENTICATOR)
	}

	if err := ai.identityDAO.Delete(ctx, req.Id, sess.OrgID,
		req.AppId); err != nil {
		return nil, errToStatus(err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		"204")); err != nil {
		logger.Errorf("DeleteIdentity grpc.SetHeader: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// ListApps retrieves all applications.
func (ai *AppIdentity) ListApps(ctx context.Context,
	req *api.ListAppsRequest) (*api.ListAppsResponse, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_VIEWER {
		return nil, errPerm(common.Role_VIEWER)
	}

	if req.PageSize == 0 {
		req.PageSize = defaultPageSize
	}

	lBoundTS, prevID, err := session.ParsePageToken(req.PageToken)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// Retrieve PageSize+1 entries to find last page.
	apps, count, err := ai.appDAO.List(ctx, sess.OrgID, lBoundTS, prevID,
		req.PageSize+1)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &api.ListAppsResponse{Apps: apps, TotalSize: count}

	// Populate next page token.
	if len(apps) == int(req.PageSize+1) {
		resp.Apps = apps[:len(apps)-1]

		if resp.NextPageToken, err = session.GeneratePageToken(
			apps[len(apps)-2].CreatedAt.AsTime(),
			apps[len(apps)-2].Id); err != nil {
			// GeneratePageToken should not error based on a DB-derived UUID.
			// Log the error and include the usable empty token.
			logger.Errorf("ListApps session.GeneratePageToken app, err: "+
				"%+v, %v", apps[len(apps)-2], err)
		}
	}

	return resp, nil
}

// ListIdentities retrieves all identities.
func (ai *AppIdentity) ListIdentities(ctx context.Context,
	req *api.ListIdentitiesRequest) (*api.ListIdentitiesResponse, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_VIEWER {
		return nil, errPerm(common.Role_VIEWER)
	}

	if req.PageSize == 0 {
		req.PageSize = defaultPageSize
	}

	lBoundTS, prevID, err := session.ParsePageToken(req.PageToken)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// Retrieve PageSize+1 entries to find last page.
	identities, count, err := ai.identityDAO.List(ctx, sess.OrgID, lBoundTS,
		prevID, req.PageSize+1, req.AppId)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &api.ListIdentitiesResponse{
		Identities: identities, TotalSize: count,
	}

	// Populate next page token.
	if len(identities) == int(req.PageSize+1) {
		resp.Identities = identities[:len(identities)-1]

		if resp.NextPageToken, err = session.GeneratePageToken(
			identities[len(identities)-2].CreatedAt.AsTime(),
			identities[len(identities)-2].Id); err != nil {
			// GeneratePageToken should not error based on a DB-derived UUID.
			// Log the error and include the usable empty token.
			logger.Errorf("ListIdentitys session.GeneratePageToken identity, "+
				"err: %+v, %v", identities[len(identities)-2], err)
		}
	}

	return resp, nil
}
