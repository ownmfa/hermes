//go:build !integration

package service

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	ikey "github.com/ownmfa/hermes/internal/hermes-api/key"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/queue"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/hermes/proto/go/message"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestCreateIdentity(t *testing.T) {
	t.Parallel()

	t.Run("Create valid HOTP identity", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_CREATED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			nil, false, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
				TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.CreateIdentityResponse{Identity: identity},
			createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.CreateIdentityResponse{
				Identity: identity,
			}, createIdentity)
		}
	})

	t.Run("Create valid SMS identity", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_CREATED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			nil, false, nil).Times(1)
		notifier := notify.NewMockNotifier(ctrl)
		notifier.EXPECT().ValidateSMS(gomock.Any(),
			identity.GetSmsMethod().GetPhone()).Return(nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN, TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, notifier, nil,
			"")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.CreateIdentityResponse{Identity: identity},
			createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.CreateIdentityResponse{
				Identity: identity,
			}, createIdentity)
		}
	})

	t.Run("Create valid Pushover identity", func(t *testing.T) {
		t.Parallel()

		identity := random.PushoverIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_CREATED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			nil, false, nil).Times(1)
		notifier := notify.NewMockNotifier(ctrl)
		notifier.EXPECT().ValidatePushover(identity.GetPushoverMethod().GetPushoverKey()).Return(nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN, TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, notifier, nil,
			"")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.CreateIdentityResponse{Identity: identity},
			createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.CreateIdentityResponse{
				Identity: identity,
			}, createIdentity)
		}
	})

	t.Run("Create valid email identity", func(t *testing.T) {
		t.Parallel()

		identity := random.EmailIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_CREATED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			nil, false, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN, TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.CreateIdentityResponse{Identity: identity},
			createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.CreateIdentityResponse{
				Identity: identity,
			}, createIdentity)
		}
	})

	t.Run("Create valid HOTP identity with OTP", func(t *testing.T) {
		t.Parallel()

		key, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d072" +
			"a5d175030b6540169b7380d58")
		require.NoError(t, err)

		b32Key := "W5WF3IGXDNLEN3JYWSBVGLG62JRC2BZKLULVAMFWKQAWTNZYBVMA"
		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: key,
		}

		app := random.App("api-app", uuid.NewString())
		identity := random.HOTPIdentity("api-identity", app.GetOrgId(), app.GetId())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_CREATED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			otp, true, nil).Times(1)
		apper := NewMockApper(ctrl)
		apper.EXPECT().Read(gomock.Any(), app.GetId(), app.GetOrgId()).
			Return(app, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
				TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, identityer, eventer, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		resp := &api.CreateIdentityResponse{Identity: identity, Secret: b32Key}

		// Normalize QR code.
		require.Greater(t, len(createIdentity.GetQr()), 800)
		resp.Qr = createIdentity.GetQr()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(resp, createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", resp, createIdentity)
		}
	})

	t.Run("Create valid backup codes identity with OTP", func(t *testing.T) {
		t.Parallel()

		key, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d072" +
			"a5d175030b6540169b7380d58")
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: key,
		}

		identity := random.BackupCodesIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_CREATED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			otp, false, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN, TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		// Normalize backup codes.
		require.Len(t, createIdentity.GetPasscodes(),
			int(identity.GetBackupCodesMethod().GetPasscodes()))

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.CreateIdentityResponse{
			Identity: identity, Passcodes: createIdentity.GetPasscodes(),
		}, createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.CreateIdentityResponse{
				Identity: identity, Passcodes: createIdentity.GetPasscodes(),
			}, createIdentity)
		}
	})

	t.Run("Create valid security questions identity", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7,
			Answer: random.String(80),
		}

		identity := random.SecurityQuestionsIdentity("api-identity",
			uuid.NewString(), uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_CREATED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			otp, false, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN, TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.CreateIdentityResponse{Identity: identity},
			createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.CreateIdentityResponse{
				Identity: identity,
			}, createIdentity)
		}
	})

	t.Run("Create identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Create identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Create identity with insufficient plan", func(t *testing.T) {
		t.Parallel()

		tests := []*api.Identity{
			random.SMSIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.PushoverIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.EmailIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.BackupCodesIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.SecurityQuestionsIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
		}

		for _, test := range tests {
			t.Run(fmt.Sprintf("Can create %v", test), func(t *testing.T) {
				t.Parallel()

				ctx, cancel := context.WithTimeout(session.NewContext(
					context.Background(), &session.Session{
						OrgID: test.GetOrgId(), OrgPlan: api.Plan_STARTER,
						Role: api.Role_ADMIN,
					}), testTimeout)
				defer cancel()

				aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
				createIdentity, err := aiSvc.CreateIdentity(ctx,
					&api.CreateIdentityRequest{Identity: test})
				t.Logf("test, createIdentity, err: %+v, %+v, %v", test,
					createIdentity, err)
				require.Nil(t, createIdentity)
				require.Equal(t, errPlan(api.Plan_PRO), err)
			})
		}
	})

	t.Run("Create identity with non-E.164 phone number", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.MethodOneof = &api.Identity_SmsMethod{
			SmsMethod: &api.SMSMethod{Phone: random.String(10)},
		}

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid E.164 phone number"), err)
	})

	t.Run("Create identity with unsupported phone number", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())

		notifier := notify.NewMockNotifier(gomock.NewController(t))
		notifier.EXPECT().ValidateSMS(gomock.Any(), identity.GetSmsMethod().
			GetPhone()).Return(notify.ErrInvalidSMS).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, notifier, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"unknown or unsupported phone number"), err)
	})

	t.Run("Create identity with unsupported Pushover key", func(t *testing.T) {
		t.Parallel()

		identity := random.PushoverIdentity("api-identity", uuid.NewString(),
			uuid.NewString())

		notifier := notify.NewMockNotifier(gomock.NewController(t))
		notifier.EXPECT().ValidatePushover(identity.GetPushoverMethod().
			GetPushoverKey()).Return(notify.ErrInvalidPushover).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, notifier, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"unknown user key"), err)
	})

	t.Run("Create invalid identity", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Comment = random.String(81)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Create(gomock.Any(), identity).Return(nil, nil,
			false, dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})

	t.Run("Create valid identity with OTP and invalid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		identity := random.HOTPIdentity("api-identity", app.GetOrgId(), app.GetId())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			&oath.OTP{}, true, nil).Times(1)
		apper := NewMockApper(ctrl)
		apper.EXPECT().Read(gomock.Any(), app.GetId(), app.GetOrgId()).Return(nil,
			dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, identityer, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})

	t.Run("Create backup codes identity with invalid OTP", func(t *testing.T) {
		t.Parallel()

		identity := random.BackupCodesIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			&oath.OTP{}, false, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.Unknown,
			"oath: unknown OATH algorithm"), err)
	})
}

func TestVerify(t *testing.T) {
	t.Parallel()

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	t.Run("Verify HOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), int64(6)).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "861821", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify soft TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.TOTP, Hash: crypto.SHA512, Digits: 7, Key: knownKey,
		}
		passcode, err := otp.TOTP(time.Now().Add(-30 * time.Second))
		require.NoError(t, err)

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), passcode), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), -1).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err = aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, passcode, oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify hard TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.TOTP, Hash: crypto.SHA512, Digits: 7, Key: knownKey,
		}
		passcode, err := otp.TOTP(time.Now().Add(-90 * time.Second))
		require.NoError(t, err)

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		identity.MethodOneof = &api.Identity_HardwareTotpMethod{}
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), passcode), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), -3).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err = aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, passcode, oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, 20)
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify SMS identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().GetI(gomock.Any(), key.Expire(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821")).Return(true, int64(0), nil).
			Times(1)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), int64(6)).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "861821", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify backup codes identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.BackupCodesIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(true, nil).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_ACTIVATED, "861821", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify security questions identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6,
			Answer: random.String(80),
		}

		identity := random.SecurityQuestionsIdentity("api-identity",
			uuid.NewString(), uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_ACTIVATED, strings.ToUpper(otp.Answer),
			oath.DefaultHOTPLookAhead, oath.DefaultTOTPLookAhead,
			oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		err := aiSvc.verify(ctx, uuid.NewString(), uuid.NewString(),
			uuid.NewString(), api.IdentityStatus_UNVERIFIED, "",
			oath.DefaultHOTPLookAhead, oath.DefaultTOTPLookAhead,
			oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Verify matching status", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.EqualError(t, err, "identity is not unverified")
	})

	t.Run("Verify by invalid expire cache", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().GetI(gomock.Any(), key.Expire(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "")).Return(false, int64(0),
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Verify by expired passcode", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().GetI(gomock.Any(), key.Expire(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "")).Return(false, int64(0), nil).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, oath.ErrInvalidPasscode, err)
	})

	t.Run("Verify by invalid reuse cache", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(false,
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "861821", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Verify by reused passcode", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(false, nil).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "861821", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, oath.ErrInvalidPasscode, err)
	})

	t.Run("Verify by invalid HOTP get cache", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "0000000"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0),
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "0000000", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Verify by invalid soft TOTP get cache", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.TOTP, Hash: crypto.SHA512, Digits: 7, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "0000000"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0),
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "0000000", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Verify by invalid hard TOTP get cache", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.TOTP, Hash: crypto.SHA512, Digits: 7, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		identity.MethodOneof = &api.Identity_HardwareTotpMethod{}
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "0000000"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0),
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "0000000", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Verify by invalid MethodOneof", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		identity.MethodOneof = nil
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "0000000"), 1).Return(true, nil).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "0000000", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, oath.ErrInvalidPasscode, err)
	})

	t.Run("Verify by invalid passcode", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "0000000"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "0000000", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, oath.ErrInvalidPasscode, err)
	})

	t.Run("Verify by invalid answer", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6,
			Answer: random.String(80),
		}

		identity := random.SecurityQuestionsIdentity("api-identity",
			uuid.NewString(), uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "answer", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, oath.ErrInvalidPasscode, err)
	})

	t.Run("Verify by invalid HOTP set cache", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), int64(6)).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, "861821", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})

	t.Run("Verify by invalid TOTP set cache", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.TOTP, Hash: crypto.SHA512, Digits: 7, Key: knownKey,
		}
		passcode, err := otp.TOTP(time.Now().Add(-30 * time.Second))
		require.NoError(t, err)

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), passcode), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), ikey.TOTPOffset(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), -1).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		err = aiSvc.verify(ctx, identity.GetId(), identity.GetOrgId(), identity.GetAppId(),
			api.IdentityStatus_UNVERIFIED, passcode, oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
	})
}

func TestActivateIdentity(t *testing.T) {
	t.Parallel()

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	t.Run("Activate HOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_ACTIVATE_SUCCESS,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		identityer.EXPECT().UpdateStatus(gomock.Any(), identity.GetId(),
			identity.GetOrgId(), identity.GetAppId(), api.IdentityStatus_ACTIVATED).
			Return(retIdentity, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), int64(6)).Return(nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
				TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, cacher, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: identity.GetId(), AppId: identity.GetAppId(), Passcode: "861821",
			})
		t.Logf("identity, activateIdentity, err: %+v, %+v, %v", identity,
			activateIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(identity, activateIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", identity, activateIdentity)
		}
	})

	t.Run("Activate identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Activate identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Activate identity that is already active", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_ACTIVATE_FAIL,
			Error: "identity is not unverified", TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
				TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: identity.GetId(), AppId: identity.GetAppId(),
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.Equal(t, status.Error(codes.FailedPrecondition,
			"identity is not unverified"), err)
	})

	t.Run("Activate identity by invalid update", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		identityer.EXPECT().UpdateStatus(gomock.Any(), identity.GetId(),
			identity.GetOrgId(), identity.GetAppId(), api.IdentityStatus_ACTIVATED).
			Return(nil, dao.ErrNotFound).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), int64(6)).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: identity.GetId(), AppId: identity.GetAppId(), Passcode: "861821",
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestChallengeIdentity(t *testing.T) {
	t.Parallel()

	t.Run("Challenge HOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_CHALLENGE_NOOP,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(identity, nil, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN, TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Challenge SMS identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), ikey.Challenge(
			identity.GetOrgId(), identity.GetAppId(), identity.GetId()), 1, notifyRate).
			Return(true, nil).Times(1)

		aiQueue := queue.NewFake()
		nInSub, err := aiQueue.Subscribe("")
		require.NoError(t, err)
		nInPubTopic := "topic-" + random.String(10)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, aiQueue,
			nInPubTopic)
		_, err = aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		select {
		case msg := <-nInSub.C():
			msg.Ack()
			t.Logf("msg.Topic, msg.Payload: %v, %s", msg.Topic(), msg.Payload())
			require.Equal(t, nInPubTopic, msg.Topic())

			res := &message.NotifierIn{}
			require.NoError(t, proto.Unmarshal(msg.Payload(), res))
			t.Logf("res: %+v", res)

			// Normalize generated trace ID.
			nIn := &message.NotifierIn{
				OrgId:      identity.GetOrgId(),
				AppId:      identity.GetAppId(),
				IdentityId: identity.GetId(),
				TraceId:    res.GetTraceId(),
			}

			// Testify does not currently support protobuf equality:
			// https://github.com/stretchr/testify/issues/758
			if !proto.Equal(nIn, res) {
				t.Fatalf("\nExpect: %+v\nActual: %+v", nIn, res)
			}
		case <-time.After(testTimeout):
			t.Fatal("Message timed out")
		}
	})

	t.Run("Challenge identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Challenge identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Challenge identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})

	t.Run("Challenge identity with insufficient plan", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(identity, nil, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_STARTER,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, errPlan(api.Plan_PRO), err)
	})

	t.Run("Challenge SMS identity by invalid rate cache", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), ikey.Challenge(
			identity.GetOrgId(), identity.GetAppId(), identity.GetId()), 1, notifyRate).
			Return(false, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})

	t.Run("Challenge SMS identity by invalid rate", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_CHALLENGE_FAIL,
			Error: "rate limit exceeded", TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), ikey.Challenge(
			identity.GetOrgId(), identity.GetAppId(), identity.GetId()), 1, notifyRate).
			Return(false, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN, TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, cacher, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.Unavailable, "rate limit exceeded"),
			err)
	})

	t.Run("Challenge SMS identity by invalid queue", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		nInPubTopic := "topic-" + random.String(10)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), ikey.Challenge(
			identity.GetOrgId(), identity.GetAppId(), identity.GetId()), 1, notifyRate).
			Return(true, nil).Times(1)
		queuer := queue.NewMockQueuer(ctrl)
		queuer.EXPECT().Publish(nInPubTopic, gomock.Any()).
			Return(dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), OrgPlan: api.Plan_PRO,
				Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, cacher, nil, queuer,
			nInPubTopic)
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.Internal, "publish failure"), err)
	})
}

func TestVerifyIdentity(t *testing.T) {
	t.Parallel()

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	t.Run("Verify HOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6, Key: knownKey,
		}

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_ACTIVATED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_VERIFY_SUCCESS,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExist(gomock.Any(), ikey.Reuse(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId(), "861821"), 1).Return(true, nil).
			Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId())).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.GetOrgId(),
			identity.GetAppId(), identity.GetId()), int64(6)).Return(nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
				TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, cacher, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(), Passcode: "861821",
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Verify identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Verify identity that is not activated", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Status = api.IdentityStatus_UNVERIFIED
		retIdentity, _ := proto.Clone(identity).(*api.Identity)
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_VERIFY_FAIL,
			Error: "identity is not activated", TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
				TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err:%v", err)
		require.Equal(t, status.Error(codes.FailedPrecondition,
			"identity is not activated"), err)
	})
}

func TestGetIdentity(t *testing.T) {
	t.Parallel()

	t.Run("Get identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(retIdentity, nil, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{Id: identity.GetId(), AppId: identity.GetAppId()})
		t.Logf("identity, getIdentity, err: %+v, %+v, %v", identity,
			getIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(identity, getIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", identity, getIdentity)
		}
	})

	t.Run("Get identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("Get identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("Get identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{
				Id: uuid.NewString(), AppId: uuid.NewString(),
			})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestDeleteIdentity(t *testing.T) {
	t.Parallel()

	t.Run("Delete identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		traceID := uuid.New()
		event := &api.Event{
			OrgId: identity.GetOrgId(), AppId: identity.GetAppId(),
			IdentityId: identity.GetId(), Status: api.EventStatus_IDENTITY_DELETED,
			TraceId: traceID.String(),
		}

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Delete(gomock.Any(), identity.GetId(), identity.GetOrgId(),
			identity.GetAppId()).Return(nil).Times(1)
		eventer := NewMockEventer(ctrl)
		eventer.EXPECT().Create(gomock.Any(), event).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.GetOrgId(), Role: api.Role_ADMIN,
				TraceID: traceID,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, eventer, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: identity.GetId(), AppId: identity.GetAppId(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Delete identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Delete identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(api.Role_AUTHENTICATOR), err)
	})

	t.Run("Delete identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestListIdentities(t *testing.T) {
	t.Parallel()

	t.Run("List identities by valid org ID", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		identities := []*api.Identity{
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
		}

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().List(gomock.Any(), orgID, time.Time{}, "",
			int32(51), "").Return(identities, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listIdentities.GetTotalSize())

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListIdentitiesResponse{
			Identities: identities, TotalSize: 3,
		}, listIdentities) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.ListIdentitiesResponse{
				Identities: identities, TotalSize: 3,
			}, listIdentities)
		}
	})

	t.Run("List identities by valid org ID with next page", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		identities := []*api.Identity{
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
		}

		next, err := session.GeneratePageToken(identities[1].GetCreatedAt().AsTime(),
			identities[1].GetId())
		require.NoError(t, err)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(3),
			"").Return(identities, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageSize: 2})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listIdentities.GetTotalSize())

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListIdentitiesResponse{
			Identities: identities[:2], NextPageToken: next, TotalSize: 3,
		}, listIdentities) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.ListIdentitiesResponse{
				Identities: identities[:2], NextPageToken: next, TotalSize: 3,
			}, listIdentities)
		}
	})

	t.Run("List identities with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.Nil(t, listIdentities)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("List identities with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.Nil(t, listIdentities)
		require.Equal(t, errPerm(api.Role_VIEWER), err)
	})

	t.Run("List identities by invalid page token", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageToken: badUUID})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.Nil(t, listIdentities)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid page token"), err)
	})

	t.Run("List identities by invalid org ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().List(gomock.Any(), "aaa", gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, int32(0),
			dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: "aaa", Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.Nil(t, listIdentities)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})

	t.Run("List identities with generation failure", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		identities := []*api.Identity{
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(),
				uuid.NewString()),
		}
		identities[1].Id = badUUID

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(3),
			"").Return(identities, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: api.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageSize: 2})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listIdentities.GetTotalSize())

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListIdentitiesResponse{
			Identities: identities[:2], TotalSize: 3,
		}, listIdentities) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.ListIdentitiesResponse{
				Identities: identities[:2], TotalSize: 3,
			}, listIdentities)
		}
	})
}
