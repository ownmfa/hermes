//go:build !unit

package test

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/api/go/message"
	ikey "github.com/ownmfa/hermes/internal/hermes-api/key"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestCreateIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
	createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
		App: random.App("api-app", uuid.NewString()),
	})
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Create valid HOTP identity with event", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId())

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.GetId(), createIdentity.GetIdentity().GetId())
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.GetIdentity().GetStatus())
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetCreatedAt().AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetUpdatedAt().AsTime(), 2*time.Second)
		require.Greater(t, len(createIdentity.GetSecret()), 50)
		require.Greater(t, len(createIdentity.GetQr()), 800)
		require.Empty(t, createIdentity.GetPasscodes())

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_IDENTITY_CREATED,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 1)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Create valid SMS identity", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			createApp.GetId())

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.GetId(), createIdentity.GetIdentity().GetId())
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.GetIdentity().GetStatus())
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetCreatedAt().AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetUpdatedAt().AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.GetSecret())
		require.Empty(t, createIdentity.GetQr())
		require.Empty(t, createIdentity.GetPasscodes())
	})

	t.Run("Create valid Pushover identity", func(t *testing.T) {
		t.Parallel()

		identity := random.PushoverIdentity("api-identity", uuid.NewString(),
			createApp.GetId())

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.GetId(), createIdentity.GetIdentity().GetId())
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.GetIdentity().GetStatus())
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetCreatedAt().AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetUpdatedAt().AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.GetSecret())
		require.Empty(t, createIdentity.GetQr())
		require.Empty(t, createIdentity.GetPasscodes())
	})

	t.Run("Create valid email identity", func(t *testing.T) {
		t.Parallel()

		identity := random.EmailIdentity("api-identity", uuid.NewString(),
			createApp.GetId())

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.GetId(), createIdentity.GetIdentity().GetId())
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.GetIdentity().GetStatus())
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetCreatedAt().AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetUpdatedAt().AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.GetSecret())
		require.Empty(t, createIdentity.GetQr())
		require.Empty(t, createIdentity.GetPasscodes())
	})

	t.Run("Create valid backup codes identity", func(t *testing.T) {
		t.Parallel()

		identity := random.BackupCodesIdentity("api-identity", uuid.NewString(),
			createApp.GetId())

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.GetId(), createIdentity.GetIdentity().GetId())
		require.Equal(t, api.IdentityStatus_ACTIVATED,
			createIdentity.GetIdentity().GetStatus())
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetCreatedAt().AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetUpdatedAt().AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.GetSecret())
		require.Empty(t, createIdentity.GetQr())
		require.Len(t, createIdentity.GetPasscodes(),
			int(identity.GetBackupCodesMethod().GetPasscodes()))
	})

	t.Run("Create valid security questions identity", func(t *testing.T) {
		t.Parallel()

		identity := random.SecurityQuestionsIdentity("api-identity",
			uuid.NewString(), createApp.GetId())

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.GetId(), createIdentity.GetIdentity().GetId())
		require.Equal(t, api.IdentityStatus_ACTIVATED,
			createIdentity.GetIdentity().GetStatus())
		require.Equal(t, "********",
			createIdentity.GetIdentity().GetSecurityQuestionsMethod().GetAnswer())
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetCreatedAt().AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.GetIdentity().GetUpdatedAt().AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.GetSecret())
		require.Empty(t, createIdentity.GetQr())
		require.Empty(t, createIdentity.GetPasscodes())
	})

	t.Run("Create valid identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					uuid.NewString()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.Nil(t, createIdentity)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, AUTHENTICATOR role required")
	})

	t.Run("Create invalid identity", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			uuid.NewString())
		identity.Comment = "api-identity-" + random.String(80)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.Nil(t, createIdentity)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid CreateIdentityRequest.Identity: embedded message failed "+
			"validation | caused by: invalid Identity.Comment: value length "+
			"must be between 5 and 80 runes, inclusive")
	})

	t.Run("Create valid identity with insufficient plan", func(t *testing.T) {
		t.Parallel()

		_, adminStarterGRPCConn, err := authGRPCConn(api.Role_ADMIN,
			api.Plan_STARTER)
		require.NoError(t, err)

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
			lTest := test

			t.Run(fmt.Sprintf("Can create %v", lTest), func(t *testing.T) {
				t.Parallel()

				ctx, cancel := context.WithTimeout(context.Background(),
					testTimeout)
				defer cancel()

				aiCli := api.NewAppIdentityServiceClient(adminStarterGRPCConn)
				createIdentity, err := aiCli.CreateIdentity(ctx,
					&api.CreateIdentityRequest{Identity: lTest})
				t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
				require.Nil(t, createIdentity)
				require.EqualError(t, err, "rpc error: code = "+
					"PermissionDenied desc = permission denied, PRO plan "+
					"required")
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

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.Nil(t, createIdentity)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid E.164 phone number")
	})
}

func TestActivateIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
	createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
		App: random.App("api-app", uuid.NewString()),
	})
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Activate HOTP identity by valid ID with event", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.GetSecret())
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 6, Key: secret,
		}
		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, key.HOTPCounter(
			activateIdentity.GetOrgId(), activateIdentity.GetAppId(),
			activateIdentity.GetId()))
		t.Logf("ok, counter, err: %v, %v, %v", ok, counter, err)
		require.True(t, ok)
		require.NoError(t, err)
		require.Equal(t, int64(6), counter)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_ACTIVATE_SUCCESS,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Activate soft TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId())
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.GetSecret())
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: secret,
		}
		passcode, err := otp.TOTP(time.Now().Add(-30 * time.Second))
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, ikey.TOTPOffset(
			activateIdentity.GetOrgId(), activateIdentity.GetAppId(),
			activateIdentity.GetId()))
		t.Logf("ok, counter, err: %v, %v, %v", ok, counter, err)
		require.True(t, ok)
		require.NoError(t, err)
		require.Equal(t, int64(-1), counter)
	})

	t.Run("Activate hard TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		randKey := make([]byte, 32)
		_, err = rand.Read(randKey)
		require.NoError(t, err)

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId())
		identity.MethodOneof = &api.Identity_HardwareTotpMethod{
			HardwareTotpMethod: &api.HardwareTOTPMethod{
				Digits: 7, Secret: randKey,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: randKey,
		}
		passcode, err := otp.TOTP(time.Now().Add(-90 * time.Second))
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, ikey.TOTPOffset(
			activateIdentity.GetOrgId(), activateIdentity.GetAppId(),
			activateIdentity.GetId()))
		t.Logf("ok, counter, err: %v, %v, %v", ok, counter, err)
		require.True(t, ok)
		require.NoError(t, err)
		require.Equal(t, int64(-3), counter)
	})

	t.Run("Activate SMS identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, otp, err := globalIdentDAO.Read(ctx, createIdentity.GetIdentity().GetId(),
			createIdentity.GetIdentity().GetOrgId(), createIdentity.GetIdentity().GetAppId())
		require.NoError(t, err)

		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		ok, err := globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.GetIdentity().GetOrgId(), createIdentity.GetIdentity().GetAppId(),
			createIdentity.GetIdentity().GetId(), passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, key.HOTPCounter(
			activateIdentity.GetOrgId(), activateIdentity.GetAppId(),
			activateIdentity.GetId()))
		t.Logf("ok, counter, err: %v, %v, %v", ok, counter, err)
		require.True(t, ok)
		require.NoError(t, err)
		require.Equal(t, int64(6), counter)
	})

	t.Run("Activate identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: uuid.NewString(), AppId: uuid.NewString(),
				Passcode: "000000",
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.EqualError(t, err, "rpc error: code = PermissionDenied "+
			"desc = permission denied, AUTHENTICATOR role required")
	})

	t.Run("Activate identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: uuid.NewString(), AppId: uuid.NewString(),
				Passcode: "000000",
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Activates are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		activateIdentity, err := secCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: "000000",
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Activate identity that is already active", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.BackupCodesIdentity("api-identity",
					uuid.NewString(), createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: "000000",
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.EqualError(t, err, "rpc error: code = FailedPrecondition desc "+
			"= identity is not unverified")

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_ACTIVATE_FAIL,
			Error:      "identity is not unverified",
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Activate identity by unknown/expired passcode", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: "000000",
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})

	t.Run("Activate identity by invalid passcode", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: "0000000",
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})
}

func TestChallengeIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
	createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
		App: random.App("api-app", uuid.NewString()),
	})
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Challenge HOTP identity by valid ID with event", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_CHALLENGE_NOOP,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Challenge SMS identity by valid ID", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		select {
		case msg := <-globalPubSub.C():
			msg.Ack()
			t.Logf("msg.Topic, msg.Payload: %v, %s", msg.Topic(), msg.Payload())
			require.Equal(t, globalPubTopic, msg.Topic())

			res := &message.NotifierIn{}
			require.NoError(t, proto.Unmarshal(msg.Payload(), res))
			t.Logf("res: %+v", res)

			// Normalize generated trace ID.
			nIn := &message.NotifierIn{
				OrgId:      createIdentity.GetIdentity().GetOrgId(),
				AppId:      createIdentity.GetIdentity().GetAppId(),
				IdentityId: createIdentity.GetIdentity().GetId(),
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

	t.Run("Challenge identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		_, err := aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, AUTHENTICATOR role required")
	})

	t.Run("Challenge identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		_, err := aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Challenges are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		_, err = secCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Challenge identity with insufficient plan", func(t *testing.T) {
		t.Parallel()

		adminStarterOrgID, adminStarterGRPCConn, err := authGRPCConn(
			api.Role_SYS_ADMIN, api.Plan_PRO)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(adminStarterGRPCConn)
		createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		// Update org fields.
		part := &api.Org{Id: adminStarterOrgID, Plan: api.Plan_STARTER}

		orgCli := api.NewOrgServiceClient(adminStarterGRPCConn)
		updateOrg, err := orgCli.UpdateOrg(ctx, &api.UpdateOrgRequest{
			Org: part, UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"plan"},
			},
		})
		t.Logf("updateOrg, err: %+v, %v", updateOrg, err)
		require.NoError(t, err)
		require.Equal(t, part.GetPlan(), updateOrg.GetPlan())

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, PRO plan required")
	})

	t.Run("Challenge SMS identity by invalid rate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		select {
		case msg := <-globalPubSub.C():
			msg.Ack()
			t.Logf("msg.Topic, msg.Payload: %v, %s", msg.Topic(), msg.Payload())
			require.Equal(t, globalPubTopic, msg.Topic())

			res := &message.NotifierIn{}
			require.NoError(t, proto.Unmarshal(msg.Payload(), res))
			t.Logf("res: %+v", res)

			// Normalize generated trace ID.
			nIn := &message.NotifierIn{
				OrgId:      createIdentity.GetIdentity().GetOrgId(),
				AppId:      createIdentity.GetIdentity().GetAppId(),
				IdentityId: createIdentity.GetIdentity().GetId(),
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

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = Unavailable desc = rate "+
			"limit exceeded")

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_CHALLENGE_FAIL,
			Error:      "rate limit exceeded",
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})
}

func TestVerifyIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
	createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
		App: random.App("api-app", uuid.NewString()),
	})
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	t.Run("Verify HOTP identity by valid ID with event", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.GetSecret())
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 6, Key: secret,
		}
		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		passcode, err = otp.HOTP(6)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_VERIFY_SUCCESS,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 3)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Verify soft TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId())
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.GetSecret())
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: secret,
		}
		passcode, err := otp.TOTP(time.Now().Add(-30 * time.Second))
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		passcode, err = otp.TOTP(time.Now())
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify hard TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		randKey := make([]byte, 32)
		_, err = rand.Read(randKey)
		require.NoError(t, err)

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId())
		identity.MethodOneof = &api.Identity_HardwareTotpMethod{
			HardwareTotpMethod: &api.HardwareTOTPMethod{
				Digits: 7, Secret: randKey,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: randKey,
		}
		passcode, err := otp.TOTP(time.Now().Add(-90 * time.Second))
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		passcode, err = otp.TOTP(time.Now().Add(-60 * time.Second))
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify SMS identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, otp, err := globalIdentDAO.Read(ctx, createIdentity.GetIdentity().GetId(),
			createIdentity.GetIdentity().GetOrgId(), createIdentity.GetIdentity().GetAppId())
		require.NoError(t, err)

		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		ok, err := globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.GetIdentity().GetOrgId(), createIdentity.GetIdentity().GetAppId(),
			createIdentity.GetIdentity().GetId(), passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		passcode, err = otp.HOTP(6)
		require.NoError(t, err)

		ok, err = globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.GetIdentity().GetOrgId(), createIdentity.GetIdentity().GetAppId(),
			createIdentity.GetIdentity().GetId(), passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify backup codes identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.BackupCodesIdentity("api-identity",
					uuid.NewString(), createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		// Verify out of order.
		for i := len(createIdentity.GetPasscodes()) - 1; i >= 0; i-- {
			_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: createIdentity.GetPasscodes()[i],
			})
			t.Logf("err: %v", err)
			require.NoError(t, err)
		}
	})

	t.Run("Verify security questions identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.SecurityQuestionsIdentity("api-identity",
			uuid.NewString(), createApp.GetId())

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: identity.GetSecurityQuestionsMethod().GetAnswer(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)
	})

	t.Run("Verify identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		_, err := aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
			Passcode: "000000",
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = PermissionDenied desc = "+
			"permission denied, AUTHENTICATOR role required")
	})

	t.Run("Verify identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		_, err := aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
			Passcode: "000000",
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Verifications are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		_, err = secCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
			Passcode: "000000",
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Verify identity that not activated", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.GetSecret())
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 6, Key: secret,
		}
		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: passcode,
		})
		t.Logf("err:%v", err)
		require.EqualError(t, err, "rpc error: code = FailedPrecondition desc "+
			"= identity is not activated")

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_VERIFY_FAIL,
			Error:      "identity is not activated",
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Verify identity by expired passcode", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, otp, err := globalIdentDAO.Read(ctx, createIdentity.GetIdentity().GetId(),
			createIdentity.GetIdentity().GetOrgId(), createIdentity.GetIdentity().GetAppId())
		require.NoError(t, err)

		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		ok, err := globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.GetIdentity().GetOrgId(), createIdentity.GetIdentity().GetAppId(),
			createIdentity.GetIdentity().GetId(), passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		passcode, err = otp.HOTP(6)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})

	t.Run("Verify identity by reused passcode", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.BackupCodesIdentity("api-identity",
					uuid.NewString(), createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: createIdentity.GetPasscodes()[0],
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: createIdentity.GetPasscodes()[0],
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})

	t.Run("Verify identity by invalid passcode", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId())
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.GetSecret())
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: secret,
		}
		passcode, err := otp.TOTP(time.Now())
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.GetStatus())
		require.WithinDuration(t, time.Now(),
			activateIdentity.GetUpdatedAt().AsTime(), 2*time.Second)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: "000000",
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})

	t.Run("Verify identity by invalid answer", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SecurityQuestionsIdentity("api-identity",
					uuid.NewString(), createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
			Passcode: random.String(80),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})
}

func TestGetIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
	createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
		App: random.App("api-app", uuid.NewString()),
	})
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	createIdentity, err := aiCli.CreateIdentity(ctx, &api.CreateIdentityRequest{
		Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId()),
	})
	t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
	require.NoError(t, err)

	t.Run("Get identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		getIdentity, err := aiCli.GetIdentity(ctx, &api.GetIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(createIdentity.GetIdentity(), getIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", createIdentity.GetIdentity(),
				getIdentity)
		}
	})

	t.Run("Get identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		getIdentity, err := aiCli.GetIdentity(ctx,
			&api.GetIdentityRequest{Id: uuid.NewString(), AppId: createApp.GetId()})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Gets are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		getIdentity, err := secCli.GetIdentity(ctx, &api.GetIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.Nil(t, getIdentity)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})
}

func TestDeleteIdentity(t *testing.T) {
	t.Parallel()

	t.Run("Delete identity by valid ID with event", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.GetIdentity().GetAppId(),
			IdentityId: createIdentity.GetIdentity().GetId(),
			Status:     api.EventStatus_IDENTITY_DELETED,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.GetIdentity().GetId(), time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].GetTraceId()
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].GetCreatedAt().AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].GetCreatedAt()

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}

		t.Run("Read identity by deleted ID", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(),
				testTimeout)
			defer cancel()

			aiCli := api.NewAppIdentityServiceClient(globalAdminKeyGRPCConn)
			getIdentity, err := aiCli.GetIdentity(ctx, &api.GetIdentityRequest{
				Id: createIdentity.GetIdentity().GetId(), AppId: uuid.NewString(),
			})
			t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
			require.Nil(t, getIdentity)
			require.EqualError(t, err, "rpc error: code = NotFound desc = "+
				"object not found")
		})
	})

	t.Run("Delete identity with insufficient role", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(secondaryViewerGRPCConn)
		_, err := aiCli.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = PermissionDenied "+
			"desc = permission denied, AUTHENTICATOR role required")
	})

	t.Run("Delete identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		_, err := aiCli.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: uuid.NewString(), AppId: uuid.NewString(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Deletes are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
			App: random.App("api-app", uuid.NewString()),
		})
		t.Logf("createApp, err: %+v, %v", createApp, err)
		require.NoError(t, err)

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.GetId()),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		_, err = secCli.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: createIdentity.GetIdentity().GetId(), AppId: createApp.GetId(),
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})
}

func TestListIdentities(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
	createApp, err := aiCli.CreateApp(ctx, &api.CreateAppRequest{
		App: random.App("api-app", uuid.NewString()),
	})
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	identityIDs := []string{}
	identityComments := []string{}
	for i := 0; i < 3; i++ {
		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.GetId())

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		identityIDs = append(identityIDs, createIdentity.GetIdentity().GetId())
		identityComments = append(identityComments,
			createIdentity.GetIdentity().GetComment())
	}

	t.Run("List identities by valid org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		listIdentities, err := aiCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageSize: 250})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(listIdentities.GetIdentities()), 3)
		require.GreaterOrEqual(t, listIdentities.GetTotalSize(), int32(3))

		var found bool
		for _, identity := range listIdentities.GetIdentities() {
			if identity.GetId() == identityIDs[len(identityIDs)-1] &&
				identity.GetComment() == identityComments[len(identityComments)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("List identities by valid org ID with next page", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminKeyGRPCConn)
		listIdentities, err := aiCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageSize: 2})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Len(t, listIdentities.GetIdentities(), 2)
		require.NotEmpty(t, listIdentities.GetNextPageToken())
		require.GreaterOrEqual(t, listIdentities.GetTotalSize(), int32(3))

		nextIdentities, err := aiCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{
				PageSize: 2, PageToken: listIdentities.GetNextPageToken(),
			})
		t.Logf("nextIdentities, err: %+v, %v", nextIdentities, err)
		require.NoError(t, err)
		require.NotEmpty(t, nextIdentities.GetIdentities())
		require.GreaterOrEqual(t, nextIdentities.GetTotalSize(), int32(3))
	})

	t.Run("List identities with app filter", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		listIdentities, err := aiCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{AppId: createApp.GetId()})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Len(t, listIdentities.GetIdentities(), 3)
		require.Equal(t, int32(3), listIdentities.GetTotalSize())

		var found bool
		for _, identity := range listIdentities.GetIdentities() {
			if identity.GetId() == identityIDs[len(identityIDs)-1] &&
				identity.GetComment() == identityComments[len(identityComments)-1] {
				found = true
			}
		}
		require.True(t, found)
	})

	t.Run("Lists are isolated by org ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		listIdentities, err := secCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Empty(t, listIdentities.GetIdentities())
		require.Equal(t, int32(0), listIdentities.GetTotalSize())
	})

	t.Run("List identities by invalid page token", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		listIdentities, err := aiCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{PageToken: badUUID})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.Nil(t, listIdentities)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"invalid page token")
	})
}
