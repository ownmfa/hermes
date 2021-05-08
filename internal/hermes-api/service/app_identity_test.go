// +build !integration

package service

import (
	"context"
	"crypto"
	"encoding/hex"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/api/go/common"
	"github.com/ownmfa/hermes/api/go/message"
	"github.com/ownmfa/hermes/internal/hermes-api/key"
	"github.com/ownmfa/hermes/internal/hermes-api/session"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/queue"
	"github.com/ownmfa/hermes/pkg/test/matcher"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestCreateApp(t *testing.T) {
	t.Parallel()

	t.Run("Create valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Create(gomock.Any(), app).Return(retApp, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{App: app})
		t.Logf("app, createApp, err: %+v, %+v, %v", app, createApp, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(app, createApp) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", app, createApp)
		}
	})

	t.Run("Create app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.Nil(t, createApp)
		require.Equal(t, errPerm(common.Role_ADMIN), err)
	})

	t.Run("Create app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.Nil(t, createApp)
		require.Equal(t, errPerm(common.Role_ADMIN), err)
	})

	t.Run("Create invalid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		app.Name = random.String(41)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Create(gomock.Any(), app).Return(nil,
			dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		createApp, err := aiSvc.CreateApp(ctx, &api.CreateAppRequest{App: app})
		t.Logf("app, createApp, err: %+v, %+v, %v", app, createApp, err)
		require.Nil(t, createApp)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})
}

func TestCreateIdentity(t *testing.T) {
	t.Parallel()

	t.Run("Create valid HOTP identity", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			nil, false, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
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

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			nil, false, nil).Times(1)
		notifier := notify.NewMockNotifier(ctrl)
		notifier.EXPECT().VaildateSMS(gomock.Any(),
			identity.GetSmsMethod().Phone).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, notifier, nil, "")
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
		identity := random.HOTPIdentity("api-identity", app.OrgId, app.Id)
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			otp, true, nil).Times(1)
		apper := NewMockApper(ctrl)
		apper.EXPECT().Read(gomock.Any(), app.Id, app.OrgId).Return(app, nil).
			Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, identityer, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.NoError(t, err)

		resp := &api.CreateIdentityResponse{Identity: identity, Secret: b32Key}

		// Normalize QR code.
		require.Greater(t, len(createIdentity.Qr), 800)
		resp.Qr = createIdentity.Qr

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(resp, createIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", resp, createIdentity)
		}
	})

	t.Run("Create identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Create identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
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
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
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

		ctrl := gomock.NewController(t)
		notifier := notify.NewMockNotifier(ctrl)
		notifier.EXPECT().VaildateSMS(gomock.Any(),
			identity.GetSmsMethod().Phone).Return(notify.ErrInvalidSMS).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, notifier, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"unknown or unsupported phone number"), err)
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
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
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
		identity := random.HOTPIdentity("api-identity", app.OrgId, app.Id)
		retIdentity, _ := proto.Clone(identity).(*api.Identity)

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Create(gomock.Any(), identity).Return(retIdentity,
			&oath.OTP{}, true, nil).Times(1)
		apper := NewMockApper(ctrl)
		apper.EXPECT().Read(gomock.Any(), app.Id, app.OrgId).Return(nil,
			dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, identityer, nil, nil, nil, "")
		createIdentity, err := aiSvc.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("identity, createIdentity, err: %+v, %+v, %v", identity,
			createIdentity, err)
		require.Nil(t, createIdentity)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "861821"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id), int64(6)).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, passcode), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id), -1).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err = aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, passcode), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id), -3).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err = aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
			api.IdentityStatus_UNVERIFIED, passcode, oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, 20)
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

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, nil, nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
			api.IdentityStatus_UNVERIFIED, "", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.FailedPrecondition,
			"identity is not unverified"), err)
	})

	t.Run("Verify by invalid reuse cache", func(t *testing.T) {
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "861821"), 1, 24*time.Hour).
			Return(false, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "861821"), 1, 24*time.Hour).
			Return(false, nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "0000000"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0),
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "0000000"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0),
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "0000000"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0),
			dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
			api.IdentityStatus_UNVERIFIED, "0000000", oath.DefaultHOTPLookAhead,
			oath.DefaultTOTPLookAhead, oath.DefaultTOTPLookAhead)
		t.Logf("err: %v", err)
		require.Equal(t, dao.ErrNotFound, err)
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "0000000"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
			api.IdentityStatus_UNVERIFIED, "0000000", oath.DefaultHOTPLookAhead,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "861821"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id), int64(6)).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err := aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, passcode), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.TOTPOffset(identity.OrgId,
			identity.AppId, identity.Id), -1).Return(dao.ErrNotFound).
			Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		err = aiSvc.verify(ctx, identity.Id, identity.OrgId, identity.AppId,
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

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		identityer.EXPECT().UpdateStatus(gomock.Any(), identity.Id,
			identity.OrgId, identity.AppId, api.IdentityStatus_ACTIVATED).
			Return(retIdentity, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "861821"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id), int64(6)).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: identity.Id, AppId: identity.AppId, Passcode: "861821",
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

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Activate identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Activate identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: uuid.NewString(), AppId: uuid.NewString(),
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		identityer.EXPECT().UpdateStatus(gomock.Any(), identity.Id,
			identity.OrgId, identity.AppId, api.IdentityStatus_ACTIVATED).
			Return(nil, dao.ErrNotFound).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "861821"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id), int64(6)).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		activateIdentity, err := aiSvc.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: identity.Id, AppId: identity.AppId, Passcode: "861821",
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

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(identity, nil, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.Id, AppId: identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Challenge(
			identity.OrgId, identity.AppId, identity.Id), 1, notifyRate).
			Return(true, nil).Times(1)

		aiQueue := queue.NewFake()
		nInSub, err := aiQueue.Subscribe("")
		require.NoError(t, err)
		nInPubTopic := "topic-" + random.String(10)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, aiQueue,
			nInPubTopic)
		_, err = aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.Id, AppId: identity.AppId,
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
				OrgId:      identity.OrgId,
				AppId:      identity.AppId,
				IdentityId: identity.Id,
				TraceId:    res.TraceId,
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

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Challenge identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Challenge identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})

	t.Run("Challenge SMS identity by invalid rate cache", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Challenge(
			identity.OrgId, identity.AppId, identity.Id), 1, notifyRate).
			Return(false, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.Id, AppId: identity.AppId,
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})

	t.Run("Challenge SMS identity by invalid rate", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			uuid.NewString())

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Challenge(
			identity.OrgId, identity.AppId, identity.Id), 1, notifyRate).
			Return(false, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.Id, AppId: identity.AppId,
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(identity, nil, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Challenge(
			identity.OrgId, identity.AppId, identity.Id), 1, notifyRate).
			Return(true, nil).Times(1)
		queuer := queue.NewMockQueuer(ctrl)
		queuer.EXPECT().Publish(nInPubTopic, gomock.Any()).
			Return(dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, queuer,
			nInPubTopic)
		_, err := aiSvc.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: identity.Id, AppId: identity.AppId,
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

		ctrl := gomock.NewController(t)
		identityer := NewMockIdentityer(ctrl)
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, otp, nil).Times(1)
		cacher := cache.NewMockCacher(ctrl)
		cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Reuse(identity.OrgId,
			identity.AppId, identity.Id, "861821"), 1, 24*time.Hour).
			Return(true, nil).Times(1)
		cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id)).Return(false, int64(0), nil).Times(1)
		cacher.EXPECT().Set(gomock.Any(), key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id), int64(6)).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, cacher, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: identity.Id, AppId: identity.AppId, Passcode: "861821",
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Verify identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Verify identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		_, err := aiSvc.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err:%v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestGetApp(t *testing.T) {
	t.Parallel()

	t.Run("Get app by valid ID", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), app.Id, app.OrgId).Return(retApp,
			nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx, &api.GetAppRequest{Id: app.Id})
		t.Logf("app, getApp, err: %+v, %+v, %v", app, getApp, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(app, getApp) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", app, getApp)
		}
	})

	t.Run("Get app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx, &api.GetAppRequest{})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("Get app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx, &api.GetAppRequest{})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("Get app by unknown ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		getApp, err := aiSvc.GetApp(ctx,
			&api.GetAppRequest{Id: uuid.NewString()})
		t.Logf("getApp, err: %+v, %v", getApp, err)
		require.Nil(t, getApp)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
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
		identityer.EXPECT().Read(gomock.Any(), identity.Id, identity.OrgId,
			identity.AppId).Return(retIdentity, nil, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: identity.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{Id: identity.Id, AppId: identity.AppId})
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

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("Get identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("Get identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		getIdentity, err := aiSvc.GetIdentity(ctx,
			&api.GetIdentityRequest{
				Id: uuid.NewString(), AppId: uuid.NewString(),
			})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestUpdateApp(t *testing.T) {
	t.Parallel()

	t.Run("Update app by valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Update(gomock.Any(), app).Return(retApp, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app,
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(app, updateApp) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", app, updateApp)
		}
	})

	t.Run("Partial update app by valid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		retApp, _ := proto.Clone(app).(*api.App)
		part := &api.App{
			Id: app.Id, Name: random.String(10), DisplayName: random.String(10),
		}
		merged := &api.App{
			Id: app.Id, OrgId: app.OrgId, Name: part.Name,
			DisplayName: part.DisplayName, Email: app.Email,
			SubjectTemplate:  app.SubjectTemplate,
			TextBodyTemplate: app.TextBodyTemplate,
			HtmlBodyTemplate: app.HtmlBodyTemplate,
		}
		retMerged, _ := proto.Clone(merged).(*api.App)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), app.Id, app.OrgId).Return(retApp,
			nil).Times(1)
		apper.EXPECT().Update(gomock.Any(), matcher.NewProtoMatcher(merged)).
			Return(retMerged, nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: part, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "display_name"},
			},
		})
		t.Logf("merged, updateApp, err: %+v, %+v, %v", merged, updateApp, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(merged, updateApp) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", merged, updateApp)
		}
	})

	t.Run("Update app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, errPerm(common.Role_ADMIN), err)
	})

	t.Run("Update app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, errPerm(common.Role_ADMIN), err)
	})

	t.Run("Update nil app", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{App: nil})
		t.Logf("updateApp, err: %+v, %v", updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid UpdateAppRequest.App: value is required"), err)
	})

	t.Run("Partial update invalid field mask", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"aaa"},
			},
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid field mask"), err)
	})

	t.Run("Partial update app by unknown app", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()
		part := &api.App{Id: uuid.NewString(), Name: random.String(10)}

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Read(gomock.Any(), part.Id, orgID).
			Return(nil, dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: part, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		t.Logf("part, updateApp, err: %+v, %+v, %v", part, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})

	t.Run("Update app validation failure", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())
		app.Name = random.String(41)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app,
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid UpdateAppRequest.App: embedded message failed "+
				"validation | caused by: invalid App.Name: value length "+
				"must be between 5 and 40 runes, inclusive"), err)
	})

	t.Run("Update app by invalid app", func(t *testing.T) {
		t.Parallel()

		app := random.App("api-app", uuid.NewString())

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Update(gomock.Any(), app).Return(nil,
			dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: app.OrgId, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		updateApp, err := aiSvc.UpdateApp(ctx, &api.UpdateAppRequest{
			App: app,
		})
		t.Logf("app, updateApp, err: %+v, %+v, %v", app, updateApp, err)
		require.Nil(t, updateApp)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})
}

func TestDeleteApp(t *testing.T) {
	t.Parallel()

	t.Run("Delete app by valid ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Delete app with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx, &api.DeleteAppRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_ADMIN), err)
	})

	t.Run("Delete app with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx, &api.DeleteAppRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_ADMIN), err)
	})

	t.Run("Delete app by unknown ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteApp(ctx,
			&api.DeleteAppRequest{Id: uuid.NewString()})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestDeleteIdentity(t *testing.T) {
	t.Parallel()

	t.Run("Delete identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Delete identity with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Delete identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_VIEWER,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{})
		t.Logf("err: %v", err)
		require.Equal(t, errPerm(common.Role_AUTHENTICATOR), err)
	})

	t.Run("Delete identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Return(dao.ErrNotFound).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		_, err := aiSvc.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.Equal(t, status.Error(codes.NotFound, "object not found"), err)
	})
}

func TestListApps(t *testing.T) {
	t.Parallel()

	t.Run("List apps by valid org ID", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		apps := []*api.App{
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
		}

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(51)).
			Return(apps, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listApps.TotalSize)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListAppsResponse{Apps: apps, TotalSize: 3},
			listApps) {
			t.Fatalf("\nExpect: %+v\nActual: %+v",
				&api.ListAppsResponse{Apps: apps, TotalSize: 3}, listApps)
		}
	})

	t.Run("List apps by valid org ID with next page", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		apps := []*api.App{
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
		}

		next, err := session.GeneratePageToken(apps[1].CreatedAt.AsTime(),
			apps[1].Id)
		require.NoError(t, err)

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(3)).
			Return(apps, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{PageSize: 2})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listApps.TotalSize)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListAppsResponse{
			Apps: apps[:2], NextPageToken: next, TotalSize: 3,
		}, listApps) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.ListAppsResponse{
				Apps: apps[:2], NextPageToken: next, TotalSize: 3,
			}, listApps)
		}
	})

	t.Run("List apps with invalid session", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("List apps with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("List apps by invalid page token", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx,
			&api.ListAppsRequest{PageToken: badUUID})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, status.Error(codes.InvalidArgument,
			"invalid page token"), err)
	})

	t.Run("List apps by invalid org ID", func(t *testing.T) {
		t.Parallel()

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), "aaa", gomock.Any(), gomock.Any(),
			gomock.Any()).Return(nil, int32(0), dao.ErrInvalidFormat).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: "aaa", Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.Nil(t, listApps)
		require.Equal(t, status.Error(codes.InvalidArgument, "invalid format"),
			err)
	})

	t.Run("List apps with generation failure", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		apps := []*api.App{
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
			random.App("api-app", uuid.NewString()),
		}
		apps[1].Id = badUUID

		apper := NewMockApper(gomock.NewController(t))
		apper.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(3)).
			Return(apps, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(apper, nil, nil, nil, nil, "")
		listApps, err := aiSvc.ListApps(ctx, &api.ListAppsRequest{PageSize: 2})
		t.Logf("listApps, err: %+v, %v", listApps, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listApps.TotalSize)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(&api.ListAppsResponse{Apps: apps[:2], TotalSize: 3},
			listApps) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", &api.ListAppsResponse{
				Apps: apps[:2], TotalSize: 3,
			}, listApps)
		}
	})
}

func TestListIdentities(t *testing.T) {
	t.Parallel()

	t.Run("List identities by valid org ID", func(t *testing.T) {
		t.Parallel()

		orgID := uuid.NewString()

		identities := []*api.Identity{
			random.HOTPIdentity("api-identity", uuid.NewString(), uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(), uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(), uuid.NewString()),
		}

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().List(gomock.Any(), orgID, time.Time{}, "",
			int32(51), "").Return(identities, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listIdentities.TotalSize)

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
			random.HOTPIdentity("api-identity", uuid.NewString(), uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(), uuid.NewString()),
			random.HOTPIdentity("api-identity", uuid.NewString(), uuid.NewString()),
		}

		next, err := session.GeneratePageToken(identities[1].CreatedAt.AsTime(),
			identities[1].Id)
		require.NoError(t, err)

		identityer := NewMockIdentityer(gomock.NewController(t))
		identityer.EXPECT().List(gomock.Any(), orgID, time.Time{}, "", int32(3),
			"").Return(identities, int32(3), nil).Times(1)

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: orgID, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageSize: 2})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listIdentities.TotalSize)

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

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.Nil(t, listIdentities)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("List identities with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ROLE_UNSPECIFIED,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.Nil(t, listIdentities)
		require.Equal(t, errPerm(common.Role_VIEWER), err)
	})

	t.Run("List identities by invalid page token", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(session.NewContext(
			context.Background(), &session.Session{
				OrgID: uuid.NewString(), Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, nil, nil, nil, nil, "")
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
				OrgID: "aaa", Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
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
				OrgID: orgID, Role: common.Role_ADMIN,
			}), testTimeout)
		defer cancel()

		aiSvc := NewAppIdentity(nil, identityer, nil, nil, nil, "")
		listIdentities, err := aiSvc.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageSize: 2})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Equal(t, int32(3), listIdentities.TotalSize)

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
