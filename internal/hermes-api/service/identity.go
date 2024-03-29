package service

//go:generate mockgen -source identity.go -destination mock_identityer_test.go -package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	ikey "github.com/ownmfa/hermes/internal/hermes-api/key"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/metric"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/proto/go/message"
	"github.com/ownmfa/proto/go/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	notifyRate = 30 * time.Second

	errExpStatus consterr.Error = "identity is not"
)

// E.164 format: https://www.twilio.com/docs/glossary/what-e164
var rePhone = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

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

// validatePlan validates notification methods and apply plan limits.
func (ai *AppIdentity) validatePlan(
	ctx context.Context, orgPlan api.Plan, i *api.Identity,
) error {
	switch m := i.GetMethodOneof().(type) {
	case *api.Identity_SmsMethod:
		if orgPlan < api.Plan_PRO {
			return errPlan(api.Plan_PRO)
		}

		if !rePhone.MatchString(m.SmsMethod.GetPhone()) {
			return status.Error(codes.InvalidArgument,
				"invalid E.164 phone number")
		}

		if err := ai.notify.ValidateSMS(ctx, m.SmsMethod.GetPhone()); err != nil {
			return errToStatus(err)
		}
	case *api.Identity_PushoverMethod:
		if orgPlan < api.Plan_PRO {
			return errPlan(api.Plan_PRO)
		}

		if err := ai.notify.ValidatePushover(
			m.PushoverMethod.GetPushoverKey()); err != nil {
			return errToStatus(err)
		}
	case *api.Identity_EmailMethod:
		if orgPlan < api.Plan_PRO {
			return errPlan(api.Plan_PRO)
		}
	case *api.Identity_BackupCodesMethod:
		if orgPlan < api.Plan_PRO {
			return errPlan(api.Plan_PRO)
		}
	case *api.Identity_SecurityQuestionsMethod:
		if orgPlan < api.Plan_PRO {
			return errPlan(api.Plan_PRO)
		}
	}

	return nil
}

// CreateIdentity creates an identity.
func (ai *AppIdentity) CreateIdentity(
	ctx context.Context, req *api.CreateIdentityRequest,
) (*api.CreateIdentityResponse, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_AUTHENTICATOR {
		return nil, errPerm(api.Role_AUTHENTICATOR)
	}

	// Validate notification methods and apply plan limits.
	if err := ai.validatePlan(ctx, sess.OrgPlan, req.GetIdentity()); err != nil {
		return nil, err
	}

	req.Identity.OrgId = sess.OrgID

	identity, otp, retSecret, err := ai.identDAO.Create(ctx, req.GetIdentity())
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &api.CreateIdentityResponse{Identity: identity}
	if retSecret {
		resp.Secret = otp.Secret()

		app, err := ai.appDAO.Read(ctx, identity.GetAppId(), sess.OrgID)
		if err != nil {
			return nil, errToStatus(err)
		}

		resp.Qr, err = otp.QR(app.GetDisplayName())
		if err != nil {
			return nil, errToStatus(err)
		}
	}

	// Populate pregenerated backup codes.
	if m, ok := identity.GetMethodOneof().(*api.Identity_BackupCodesMethod); ok {
		for i := range m.BackupCodesMethod.GetPasscodes() {
			passcode, err := otp.HOTP(int64(i + 10))
			if err != nil {
				return nil, errToStatus(err)
			}

			resp.Passcodes = append(resp.GetPasscodes(), passcode)
		}
	}

	// Failure to write an event is non-fatal, but should be logged for
	// investigation.
	event := &api.Event{
		OrgId:      identity.GetOrgId(),
		AppId:      identity.GetAppId(),
		IdentityId: identity.GetId(),
		Status:     api.EventStatus_IDENTITY_CREATED,
		TraceId:    sess.TraceID.String(),
	}
	if err = ai.evDAO.Create(ctx, event); err != nil {
		logger.Errorf("CreateIdentity ai.evDAO.Create: %v", err)
	}

	if err = grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		strconv.Itoa(http.StatusCreated))); err != nil {
		logger.Errorf("CreateIdentity grpc.SetHeader: %v", err)
	}

	return resp, nil
}

// verify verifies a passcode and stores the HOTP counter or TOTP window offset.
func (ai *AppIdentity) verify(
	ctx context.Context, identityID, orgID, appID string,
	expStatus api.IdentityStatus, passcode string, hotpLookAhead,
	softTOTPLookAhead, hardTOTPLookAhead int,
) error {
	identity, otp, err := ai.identDAO.Read(ctx, identityID, orgID, appID)
	if err != nil {
		return err
	}

	if identity.GetStatus() != expStatus {
		return fmt.Errorf("%w %s", errExpStatus,
			strings.ToLower(expStatus.String()))
	}

	// Check passcode expiration for methods that utilize it. Continue to
	// verification, even if found, to keep HOTP counters in sync.
	switch identity.GetMethodOneof().(type) {
	case *api.Identity_SmsMethod, *api.Identity_PushoverMethod,
		*api.Identity_EmailMethod:
		ok, _, err := ai.cache.GetI(ctx, key.Expire(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), passcode))
		if err != nil {
			return err
		}
		if !ok {
			return oath.ErrInvalidPasscode
		}
	}

	// Disallow passcode reuse, even when counter tracking would prevent it. Do
	// not expire to support backup codes.
	if _, ok := identity.GetMethodOneof().(*api.Identity_SecurityQuestionsMethod); !ok {
		ok, err := ai.cache.SetIfNotExist(ctx, ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), passcode), 1)
		if err != nil {
			return err
		}
		if !ok {
			return oath.ErrInvalidPasscode
		}
	}

	// Add logging fields.
	logger := hlog.FromContext(ctx)
	logger.Logger = logger.WithField("appID", identity.GetAppId())
	logger.Logger = logger.WithField("identityID", identity.GetId())

	// Verify passcode and calculate HOTP counter or TOTP window offset.
	var counter int64
	var offset int

	switch identity.GetMethodOneof().(type) {
	case *api.Identity_SoftwareHotpMethod, *api.Identity_GoogleAuthHotpMethod,
		*api.Identity_HardwareHotpMethod, *api.Identity_SmsMethod,
		*api.Identity_PushoverMethod, *api.Identity_EmailMethod:
		// Retrieve current HOTP counter. If not found, use the zero value.
		var curr int64
		_, curr, err = ai.cache.GetI(ctx, key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()))
		if err != nil {
			return err
		}

		counter, err = otp.VerifyHOTP(hotpLookAhead, curr, passcode)
	case *api.Identity_SoftwareTotpMethod, *api.Identity_GoogleAuthTotpMethod,
		*api.Identity_AppleIosTotpMethod:
		// Retrieve TOTP window offset. If not found, use the zero value.
		var off int64
		_, off, err = ai.cache.GetI(ctx, ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()))
		if err != nil {
			return err
		}

		offset, err = otp.VerifyTOTP(softTOTPLookAhead, int(off), passcode)
	case *api.Identity_HardwareTotpMethod:
		// Retrieve TOTP window offset. If not found, use the zero value.
		var off int64
		_, off, err = ai.cache.GetI(ctx, ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()))
		if err != nil {
			return err
		}

		offset, err = otp.VerifyTOTP(hardTOTPLookAhead, int(off), passcode)
	case *api.Identity_BackupCodesMethod:
		// Backup codes may be used out of order, always use a zero value HOTP
		// counter and do not store the new counter. Do not apply plan limits,
		// as backup codes are limited in quantity.
		_, err = otp.VerifyHOTP(hotpLookAhead, 0, passcode)
	case *api.Identity_SecurityQuestionsMethod:
		if subtle.ConstantTimeCompare([]byte(otp.Answer),
			[]byte(strings.ToLower(passcode))) == 0 {
			err = oath.ErrInvalidPasscode
		}
	default:
		logger.Errorf("verify unknown identity.MethodOneof: %+v", identity)

		err = oath.ErrInvalidPasscode
	}
	if err != nil {
		return err
	}

	// Store HOTP counter or TOTP window offset for future verifications.
	switch {
	case counter != 0:
		if err = ai.cache.Set(ctx, key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), counter); err != nil {
			return err
		}
	case offset != 0:
		if err = ai.cache.Set(ctx, ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), offset); err != nil {
			return err
		}
	}
	logger.Infof("verify counter, offset: %v, %v", counter, offset)

	return nil
}

// ActivateIdentity activates an identity by ID.
func (ai *AppIdentity) ActivateIdentity(
	ctx context.Context, req *api.ActivateIdentityRequest,
) (*api.Identity, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_AUTHENTICATOR {
		return nil, errPerm(api.Role_AUTHENTICATOR)
	}

	// Build event skeleton and function to write it. Failure to write an event
	// is non-fatal, but should be logged for investigation.
	writeEvent := func(status api.EventStatus, err string) {
		event := &api.Event{
			OrgId:      sess.OrgID,
			AppId:      req.GetAppId(),
			IdentityId: req.GetId(),
			Status:     status,
			Error:      err,
			TraceId:    sess.TraceID.String(),
		}

		if wErr := ai.evDAO.Create(ctx, event); wErr != nil {
			logger.Errorf("ActivateIdentity writeEvent: %v", wErr)
		}
	}

	if err := ai.verify(ctx, req.GetId(), sess.OrgID, req.GetAppId(),
		api.IdentityStatus_UNVERIFIED, req.GetPasscode(), 1000, 6, 20); err != nil {
		if errors.Is(err, errExpStatus) ||
			errors.Is(err, oath.ErrInvalidPasscode) {
			writeEvent(api.EventStatus_ACTIVATE_FAIL, err.Error())
		}

		return nil, errToStatus(err)
	}

	identity, err := ai.identDAO.UpdateStatus(ctx, req.GetId(), sess.OrgID,
		req.GetAppId(), api.IdentityStatus_ACTIVATED)
	if err != nil {
		return nil, errToStatus(err)
	}

	writeEvent(api.EventStatus_ACTIVATE_SUCCESS, "")

	return identity, nil
}

// ChallengeIdentity issues a challenge to an identity by ID.
func (ai *AppIdentity) ChallengeIdentity(
	ctx context.Context, req *api.ChallengeIdentityRequest,
) (*emptypb.Empty, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_AUTHENTICATOR {
		return nil, errPerm(api.Role_AUTHENTICATOR)
	}

	identity, _, err := ai.identDAO.Read(ctx, req.GetId(), sess.OrgID,
		req.GetAppId())
	if err != nil {
		return nil, errToStatus(err)
	}

	// Build event skeleton and function to write it. Failure to write an event
	// is non-fatal, but should be logged for investigation.
	writeEvent := func(status api.EventStatus, err string) {
		event := &api.Event{
			OrgId:      identity.GetOrgId(),
			AppId:      identity.GetAppId(),
			IdentityId: identity.GetId(),
			Status:     status,
			Error:      err,
			TraceId:    sess.TraceID.String(),
		}

		if wErr := ai.evDAO.Create(ctx, event); wErr != nil {
			logger.Errorf("ChallengeIdentity writeEvent: %v", wErr)
		}
	}

	// Build and publish NotifierIn message for methods that utilize it.
	switch identity.GetMethodOneof().(type) {
	case *api.Identity_SmsMethod, *api.Identity_PushoverMethod,
		*api.Identity_EmailMethod:
		// Apply plan limits, in the event that the organization's plan was
		// lowered after identity creation.
		if sess.OrgPlan < api.Plan_PRO {
			return nil, errPlan(api.Plan_PRO)
		}

		// Rate limit.
		notifyKey := ikey.Challenge(identity.GetOrgId(), identity.GetAppId(), identity.GetId())
		ok, err := ai.cache.SetIfNotExistTTL(ctx, notifyKey, 1, notifyRate)
		if err != nil {
			return nil, errToStatus(err)
		}
		if !ok {
			writeEvent(api.EventStatus_CHALLENGE_FAIL, "rate limit exceeded")

			if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
				"429")); err != nil {
				logger.Errorf("ChallengeIdentity grpc.SetHeader: %v", err)
			}

			return nil, status.Error(codes.Unavailable, "rate limit exceeded")
		}

		// Add logging fields.
		logger.Logger = logger.WithField("appID", identity.GetAppId())
		logger.Logger = logger.WithField("identityID", identity.GetId())

		nIn := &message.NotifierIn{
			OrgId:      identity.GetOrgId(),
			AppId:      identity.GetAppId(),
			IdentityId: identity.GetId(),
			TraceId:    sess.TraceID[:],
		}

		// Build and publish NotifierIn message.
		bNIn, err := proto.Marshal(nIn)
		if err != nil {
			logger.Errorf("ChallengeIdentity proto.Marshal: %v", err)

			return nil, status.Error(codes.Internal, "encode failure")
		}

		if err = ai.aiQueue.Publish(ai.nInPubTopic, bNIn); err != nil {
			logger.Errorf("ChallengeIdentity ai.aiQueue.Publish: %v", err)

			return nil, status.Error(codes.Internal, "publish failure")
		}

		metric.Incr("published", nil)
		logger.Debug("ChallengeIdentity published")

		if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
			strconv.Itoa(http.StatusAccepted))); err != nil {
			logger.Errorf("ChallengeIdentity grpc.SetHeader: %v", err)
		}

		return &emptypb.Empty{}, nil
	}

	writeEvent(api.EventStatus_CHALLENGE_NOOP, "")

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		strconv.Itoa(http.StatusNoContent))); err != nil {
		logger.Errorf("ChallengeIdentity grpc.SetHeader: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// VerifyIdentity verifies an identity by ID.
func (ai *AppIdentity) VerifyIdentity(
	ctx context.Context, req *api.VerifyIdentityRequest,
) (*emptypb.Empty, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_AUTHENTICATOR {
		return nil, errPerm(api.Role_AUTHENTICATOR)
	}

	// Build event skeleton and function to write it. Failure to write an event
	// is non-fatal, but should be logged for investigation.
	writeEvent := func(status api.EventStatus, err string) {
		event := &api.Event{
			OrgId:      sess.OrgID,
			AppId:      req.GetAppId(),
			IdentityId: req.GetId(),
			Status:     status,
			Error:      err,
			TraceId:    sess.TraceID.String(),
		}

		if wErr := ai.evDAO.Create(ctx, event); wErr != nil {
			logger.Errorf("VerifyIdentity writeEvent: %v", wErr)
		}
	}

	if err := ai.verify(ctx, req.GetId(), sess.OrgID, req.GetAppId(),
		api.IdentityStatus_ACTIVATED, req.GetPasscode(), oath.DefaultHOTPLookAhead,
		oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead); err != nil {
		if errors.Is(err, errExpStatus) ||
			errors.Is(err, oath.ErrInvalidPasscode) {
			writeEvent(api.EventStatus_VERIFY_FAIL, err.Error())
		}

		return nil, errToStatus(err)
	}

	writeEvent(api.EventStatus_VERIFY_SUCCESS, "")

	return &emptypb.Empty{}, nil
}

// GetIdentity retrieves an identity by ID.
func (ai *AppIdentity) GetIdentity(
	ctx context.Context, req *api.GetIdentityRequest,
) (*api.Identity, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_VIEWER {
		return nil, errPerm(api.Role_VIEWER)
	}

	identity, _, err := ai.identDAO.Read(ctx, req.GetId(), sess.OrgID, req.GetAppId())
	if err != nil {
		return nil, errToStatus(err)
	}

	return identity, nil
}

// DeleteIdentity deletes an identity by ID.
func (ai *AppIdentity) DeleteIdentity(
	ctx context.Context, req *api.DeleteIdentityRequest,
) (*emptypb.Empty, error) {
	logger := hlog.FromContext(ctx)
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_AUTHENTICATOR {
		return nil, errPerm(api.Role_AUTHENTICATOR)
	}

	if err := ai.identDAO.Delete(ctx, req.GetId(), sess.OrgID,
		req.GetAppId()); err != nil {
		return nil, errToStatus(err)
	}

	// Failure to write an event is non-fatal, but should be logged for
	// investigation.
	event := &api.Event{
		OrgId:      sess.OrgID,
		AppId:      req.GetAppId(),
		IdentityId: req.GetId(),
		Status:     api.EventStatus_IDENTITY_DELETED,
		TraceId:    sess.TraceID.String(),
	}
	if err := ai.evDAO.Create(ctx, event); err != nil {
		logger.Errorf("DeleteIdentity ai.evDAO.Create: %v", err)
	}

	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeKey,
		strconv.Itoa(http.StatusNoContent))); err != nil {
		logger.Errorf("DeleteIdentity grpc.SetHeader: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// ListIdentities retrieves all identities.
func (ai *AppIdentity) ListIdentities(
	ctx context.Context, req *api.ListIdentitiesRequest,
) (*api.ListIdentitiesResponse, error) {
	sess, ok := session.FromContext(ctx)
	if !ok || sess.Role < api.Role_VIEWER {
		return nil, errPerm(api.Role_VIEWER)
	}

	if req.GetPageSize() == 0 {
		req.PageSize = defaultPageSize
	}

	lBoundTS, prevID, err := session.ParsePageToken(req.GetPageToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// Retrieve PageSize+1 entries to find last page.
	identities, count, err := ai.identDAO.List(ctx, sess.OrgID, lBoundTS,
		prevID, req.GetPageSize()+1, req.GetAppId())
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &api.ListIdentitiesResponse{
		Identities: identities, TotalSize: count,
	}

	// Populate next page token.
	if len(identities) == int(req.GetPageSize()+1) {
		resp.Identities = identities[:len(identities)-1]

		if resp.NextPageToken, err = session.GeneratePageToken(
			identities[len(identities)-2].GetCreatedAt().AsTime(),
			identities[len(identities)-2].GetId()); err != nil {
			// GeneratePageToken should not error based on a DB-derived UUID.
			// Log the error and include the usable empty token.
			logger := hlog.FromContext(ctx)
			logger.Errorf("ListIdentitys session.GeneratePageToken identity, "+
				"err: %+v, %v", identities[len(identities)-2], err)
		}
	}

	return resp, nil
}
