package service

//go:generate mockgen -source app_identity.go -destination mock_apper_test.go -package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mennanov/fmutils"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/api/go/common"
	"github.com/ownmfa/hermes/api/go/message"
	"github.com/ownmfa/hermes/internal/hermes-api/key"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/queue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// E.164 format: https://www.twilio.com/docs/glossary/what-e164
var rePhone = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

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

	notify notify.Notifier

	aiQueue     queue.Queuer
	nInPubTopic string
}

// NewAppIdentity instantiates and returns a new AppIdentity service.
func NewAppIdentity(appDAO Apper, identityDAO Identityer, cache cache.Cacher,
	notify notify.Notifier, pubQueue queue.Queuer,
	pubTopic string) *AppIdentity {
	return &AppIdentity{
		appDAO:      appDAO,
		identityDAO: identityDAO,
		cache:       cache,

		notify: notify,

		aiQueue:     pubQueue,
		nInPubTopic: pubTopic,
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

	// Validate phone number, if present.
	if sms, ok := req.Identity.MethodOneof.(*api.Identity_SmsMethod); ok {
		if !rePhone.MatchString(sms.SmsMethod.Phone) {
			return nil, status.Error(codes.InvalidArgument,
				"invalid E.164 phone number")
		}

		if err := ai.notify.VaildateSMS(ctx, sms.SmsMethod.Phone); err != nil {
			return nil, errToStatus(err)
		}
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

// verify verifies a passcode and stores the HOTP counter or TOTP window offset.
func (ai *AppIdentity) verify(ctx context.Context, identityID, orgID,
	appID string, expStatus api.IdentityStatus, passcode string, hotpLookAhead,
	softTOTPLookAhead, hardTOTPLookAhead int) error {
	identity, otp, err := ai.identityDAO.Read(ctx, identityID, orgID, appID)
	if err != nil {
		return err
	}

	if identity.Status != expStatus {
		return status.Error(codes.FailedPrecondition,
			fmt.Sprintf("identity is not %s",
				strings.ToLower(expStatus.String())))
	}

	// Disallow passcode reuse, even when counter tracking would prevent it.
	ok, err := ai.cache.SetIfNotExistTTL(ctx, key.Reuse(identity.OrgId,
		identity.AppId, identity.Id, passcode), 1, 24*time.Hour)
	if err != nil {
		return err
	}
	for !ok {
		return oath.ErrInvalidPasscode
	}

	// Verify passcode and calculate HOTP counter or TOTP window offset.
	var counter int64
	var offset int

	switch identity.MethodOneof.(type) {
	case *api.Identity_SoftwareHotpMethod, *api.Identity_GoogleAuthHotpMethod,
		*api.Identity_HardwareHotpMethod:
		// Retrieve current HOTP counter. If not found, use the zero value.
		var curr int64
		_, curr, err = ai.cache.GetI(ctx, key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id))
		if err != nil {
			return err
		}

		counter, err = otp.VerifyHOTP(hotpLookAhead, curr, passcode)
	case *api.Identity_SoftwareTotpMethod, *api.Identity_GoogleAuthTotpMethod,
		*api.Identity_MicrosoftAuthTotpMethod:
		// Retrieve TOTP window offset. If not found, use the zero value.
		var off int64
		_, off, err = ai.cache.GetI(ctx, key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id))
		if err != nil {
			return err
		}

		offset, err = otp.VerifyTOTP(softTOTPLookAhead, int(off), passcode)
	case *api.Identity_HardwareTotpMethod:
		// Retrieve TOTP window offset. If not found, use the zero value.
		var off int64
		_, off, err = ai.cache.GetI(ctx, key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id))
		if err != nil {
			return err
		}

		offset, err = otp.VerifyTOTP(hardTOTPLookAhead, int(off), passcode)
	}
	if err != nil {
		return err
	}

	// Add logging fields.
	logger := hlog.FromContext(ctx)
	logger.Logger = logger.WithStr("appID", identity.AppId)
	logger.Logger = logger.WithStr("identityID", identity.Id)
	logger.Infof("verify counter, offset: %v, %v", counter, offset)

	// Store HOTP counter or TOTP window offset for future verifications.
	switch {
	case counter != 0:
		if err = ai.cache.Set(ctx, key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id), counter); err != nil {
			return err
		}
	case offset != 0:
		if err = ai.cache.Set(ctx, key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id), offset); err != nil {
			return err
		}
	}

	return nil
}

// ActivateIdentity activates an identity by ID.
func (ai *AppIdentity) ActivateIdentity(ctx context.Context,
	req *api.ActivateIdentityRequest) (*api.Identity, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_AUTHENTICATOR {
		return nil, errPerm(common.Role_AUTHENTICATOR)
	}

	if err := ai.verify(ctx, req.Id, sess.OrgID, req.AppId,
		api.IdentityStatus_UNVERIFIED, req.Passcode, 1000, 6, 20); err != nil {
		return nil, errToStatus(err)
	}

	identity, err := ai.identityDAO.UpdateStatus(ctx, req.Id, sess.OrgID,
		req.AppId, api.IdentityStatus_ACTIVATED)
	if err != nil {
		return nil, errToStatus(err)
	}

	return identity, nil
}

// ChallengeIdentity issues a challenge to an identity by ID.
func (ai *AppIdentity) ChallengeIdentity(ctx context.Context,
	req *api.ChallengeIdentityRequest) (*emptypb.Empty, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_AUTHENTICATOR {
		return nil, errPerm(common.Role_AUTHENTICATOR)
	}

	// Verify an identity exists, even in cases where no challenge is sent.
	identity, _, err := ai.identityDAO.Read(ctx, req.Id, sess.OrgID,
		req.AppId)
	if err != nil {
		return nil, errToStatus(err)
	}

	// Build and publish NotifierIn message for methods that require it.
	if _, ok := identity.MethodOneof.(*api.Identity_SmsMethod); ok {
		// Add logging fields.
		traceID := uuid.New()
		logger.Logger = logger.WithStr("traceID", traceID.String())
		logger.Logger = logger.WithStr("appID", identity.AppId)
		logger.Logger = logger.WithStr("identityID", identity.Id)

		nIn := &message.NotifierIn{
			OrgId:      identity.OrgId,
			AppId:      identity.AppId,
			IdentityId: identity.Id,
			TraceId:    traceID[:],
		}

		bNIn, err := proto.Marshal(nIn)
		if err != nil {
			logger.Errorf("ChallengeIdentity proto.Marshal: %v", err)

			return nil, status.Error(codes.Internal, "encode failure")
		}

		if err = ai.aiQueue.Publish(ai.nInPubTopic, bNIn); err != nil {
			logger.Errorf("ChallengeIdentity ai.aiQueue.Publish: %v", err)

			return nil, status.Error(codes.Internal, "publish failure")
		}

		logger.Debugf("ChallengeIdentity published: %+v", nIn)
		if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
			"202")); err != nil {
			logger.Errorf("ChallengeIdentity grpc.SetHeader: %v", err)
		}

		return &emptypb.Empty{}, nil
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		"204")); err != nil {
		logger.Errorf("ChallengeIdentity grpc.SetHeader: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// VerifyIdentity verifies an identity by ID.
func (ai *AppIdentity) VerifyIdentity(ctx context.Context,
	req *api.VerifyIdentityRequest) (*emptypb.Empty, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < common.Role_AUTHENTICATOR {
		return nil, errPerm(common.Role_AUTHENTICATOR)
	}

	if err := ai.verify(ctx, req.Id, sess.OrgID, req.AppId,
		api.IdentityStatus_ACTIVATED, req.Passcode, oath.DefaultHOTPLookAhead,
		oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead); err != nil {
		return nil, errToStatus(err)
	}

	return &emptypb.Empty{}, nil
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
