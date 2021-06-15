// +build !unit

package test

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base32"
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
			createApp.Id)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.Id, createIdentity.Identity.Id)
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.Identity.Status)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.CreatedAt.AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.UpdatedAt.AsTime(), 2*time.Second)
		require.Greater(t, len(createIdentity.Secret), 50)
		require.Greater(t, len(createIdentity.Qr), 800)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_IDENTITY_CREATED,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 1)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Create valid SMS identity", func(t *testing.T) {
		t.Parallel()

		identity := random.SMSIdentity("api-identity", uuid.NewString(),
			createApp.Id)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.Id, createIdentity.Identity.Id)
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.Identity.Status)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.CreatedAt.AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.UpdatedAt.AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.Secret)
		require.Empty(t, createIdentity.Qr)
	})

	t.Run("Create valid Pushover identity", func(t *testing.T) {
		t.Parallel()

		identity := random.PushoverIdentity("api-identity", uuid.NewString(),
			createApp.Id)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.Id, createIdentity.Identity.Id)
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.Identity.Status)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.CreatedAt.AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.UpdatedAt.AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.Secret)
		require.Empty(t, createIdentity.Qr)
	})

	t.Run("Create valid email identity", func(t *testing.T) {
		t.Parallel()

		identity := random.EmailIdentity("api-identity", uuid.NewString(),
			createApp.Id)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)
		require.NotEqual(t, identity.Id, createIdentity.Identity.Id)
		require.Equal(t, api.IdentityStatus_UNVERIFIED,
			createIdentity.Identity.Status)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.CreatedAt.AsTime(), 2*time.Second)
		require.WithinDuration(t, time.Now(),
			createIdentity.Identity.UpdatedAt.AsTime(), 2*time.Second)
		require.Empty(t, createIdentity.Secret)
		require.Empty(t, createIdentity.Qr)
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 6, Key: secret,
		}
		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, key.HOTPCounter(
			activateIdentity.OrgId, activateIdentity.AppId,
			activateIdentity.Id))
		t.Logf("ok, counter, err: %v, %v, %v", ok, counter, err)
		require.True(t, ok)
		require.NoError(t, err)
		require.Equal(t, int64(6), counter)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_ACTIVATE_SUCCESS,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Activate soft TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.Id)
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: secret,
		}
		passcode, err := otp.TOTP(time.Now().Add(-30 * time.Second))
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, ikey.TOTPOffset(
			activateIdentity.OrgId, activateIdentity.AppId,
			activateIdentity.Id))
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
			createApp.Id)
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
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, ikey.TOTPOffset(
			activateIdentity.OrgId, activateIdentity.AppId,
			activateIdentity.Id))
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, otp, err := globalIdentDAO.Read(ctx, createIdentity.Identity.Id,
			createIdentity.Identity.OrgId, createIdentity.Identity.AppId)
		require.NoError(t, err)

		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		ok, err := globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.Identity.OrgId, createIdentity.Identity.AppId,
			createIdentity.Identity.Id, passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		ok, counter, err := globalCache.GetI(ctx, key.HOTPCounter(
			activateIdentity.OrgId, activateIdentity.AppId,
			activateIdentity.Id))
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		activateIdentity, err := secCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
				Identity: random.HOTPIdentity("api-identity", uuid.NewString(),
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 6, Key: secret,
		}
		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		activateIdentity, err = aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.Nil(t, activateIdentity)
		require.EqualError(t, err, "rpc error: code = FailedPrecondition desc "+
			"= identity is not unverified")

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_ACTIVATE_FAIL,
			Error:      "identity is not unverified",
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 3)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Activate identity by expired passcode", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_CHALLENGE_NOOP,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
				OrgId:      createIdentity.Identity.OrgId,
				AppId:      createIdentity.Identity.AppId,
				IdentityId: createIdentity.Identity.Id,
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		_, err = secCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = NotFound desc = object "+
			"not found")
	})

	t.Run("Challenge SMS identity by invalid rate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{
				Identity: random.SMSIdentity("api-identity", uuid.NewString(),
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
				OrgId:      createIdentity.Identity.OrgId,
				AppId:      createIdentity.Identity.AppId,
				IdentityId: createIdentity.Identity.Id,
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

		_, err = aiCli.ChallengeIdentity(ctx, &api.ChallengeIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = Unavailable desc = rate "+
			"limit exceeded")

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_CHALLENGE_FAIL,
			Error:      "rate limit exceeded",
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 6, Key: secret,
		}
		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		passcode, err = otp.HOTP(6)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_VERIFY_SUCCESS,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 3)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(event, listEvents[0]) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", event, listEvents[0])
		}
	})

	t.Run("Verify soft TOTP identity by valid ID", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.Id)
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: secret,
		}
		passcode, err := otp.TOTP(time.Now().Add(-30 * time.Second))
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		passcode, err = otp.TOTP(time.Now())
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
			createApp.Id)
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
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		passcode, err = otp.TOTP(time.Now().Add(-60 * time.Second))
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, otp, err := globalIdentDAO.Read(ctx, createIdentity.Identity.Id,
			createIdentity.Identity.OrgId, createIdentity.Identity.AppId)
		require.NoError(t, err)

		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		ok, err := globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.Identity.OrgId, createIdentity.Identity.AppId,
			createIdentity.Identity.Id, passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		passcode, err = otp.HOTP(6)
		require.NoError(t, err)

		ok, err = globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.Identity.OrgId, createIdentity.Identity.AppId,
			createIdentity.Identity.Id, passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
			Passcode: passcode,
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
					createApp.Id),
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 6, Key: secret,
		}
		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
			Passcode: passcode,
		})
		t.Logf("err:%v", err)
		require.EqualError(t, err, "rpc error: code = FailedPrecondition desc "+
			"= identity is not activated")

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_VERIFY_FAIL,
			Error:      "identity is not activated",
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, otp, err := globalIdentDAO.Read(ctx, createIdentity.Identity.Id,
			createIdentity.Identity.OrgId, createIdentity.Identity.AppId)
		require.NoError(t, err)

		passcode, err := otp.HOTP(5)
		require.NoError(t, err)

		ok, err := globalCache.SetIfNotExist(ctx, key.Expire(
			createIdentity.Identity.OrgId, createIdentity.Identity.AppId,
			createIdentity.Identity.Id, passcode), 1)
		require.True(t, ok)
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		passcode, err = otp.HOTP(6)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})

	t.Run("Verify identity by reused passcode", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.Id)
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: secret,
		}
		passcode, err := otp.TOTP(time.Now().Add(-30 * time.Second))
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		passcode, err = otp.TOTP(time.Now())
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
			Passcode: passcode,
		})
		t.Logf("err: %v", err)
		require.EqualError(t, err, "rpc error: code = InvalidArgument desc = "+
			"oath: invalid passcode")
	})

	t.Run("Verify identity by invalid passcode", func(t *testing.T) {
		t.Parallel()

		identity := random.HOTPIdentity("api-identity", uuid.NewString(),
			createApp.Id)
		identity.MethodOneof = &api.Identity_SoftwareTotpMethod{}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
		secret, err := base32NoPad.DecodeString(createIdentity.Secret)
		require.NoError(t, err)

		otp := &oath.OTP{
			Algorithm: oath.HOTP, Hash: crypto.SHA512, Digits: 7, Key: secret,
		}
		passcode, err := otp.TOTP(time.Now())
		require.NoError(t, err)

		activateIdentity, err := aiCli.ActivateIdentity(ctx,
			&api.ActivateIdentityRequest{
				Id: createIdentity.Identity.Id, AppId: createApp.Id,
				Passcode: passcode,
			})
		t.Logf("activateIdentity, err: %+v, %v", activateIdentity, err)
		require.NoError(t, err)
		require.Equal(t, api.IdentityStatus_ACTIVATED, activateIdentity.Status)
		require.WithinDuration(t, time.Now(),
			activateIdentity.UpdatedAt.AsTime(), 2*time.Second)

		_, err = aiCli.VerifyIdentity(ctx, &api.VerifyIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
			Passcode: "000000",
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
			createApp.Id),
	})
	t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
	require.NoError(t, err)

	t.Run("Get identity by valid ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		getIdentity, err := aiCli.GetIdentity(ctx, &api.GetIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
		})
		t.Logf("getIdentity, err: %+v, %v", getIdentity, err)
		require.NoError(t, err)

		// Testify does not currently support protobuf equality:
		// https://github.com/stretchr/testify/issues/758
		if !proto.Equal(createIdentity.Identity, getIdentity) {
			t.Fatalf("\nExpect: %+v\nActual: %+v", createIdentity.Identity,
				getIdentity)
		}
	})

	t.Run("Get identity by unknown ID", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		getIdentity, err := aiCli.GetIdentity(ctx,
			&api.GetIdentityRequest{Id: uuid.NewString(), AppId: createApp.Id})
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
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		_, err = aiCli.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
		})
		t.Logf("err: %v", err)
		require.NoError(t, err)

		// Verify event.
		event := &api.Event{
			OrgId:      globalAdminOrgID,
			AppId:      createIdentity.Identity.AppId,
			IdentityId: createIdentity.Identity.Id,
			Status:     api.EventStatus_IDENTITY_DELETED,
		}

		listEvents, err := globalEvDAO.List(ctx, globalAdminOrgID,
			createIdentity.Identity.Id, time.Now(),
			time.Now().Add(-testTimeout))
		t.Logf("listEvents, err: %+v, %v", listEvents, err)
		require.NoError(t, err)
		require.Len(t, listEvents, 2)

		// Normalize generated trace ID.
		event.TraceId = listEvents[0].TraceId
		// Normalize timestamp.
		require.WithinDuration(t, time.Now(),
			listEvents[0].CreatedAt.AsTime(), testTimeout)
		event.CreatedAt = listEvents[0].CreatedAt

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
				Id: createIdentity.Identity.Id, AppId: uuid.NewString(),
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
					createApp.Id),
			})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		secCli := api.NewAppIdentityServiceClient(secondaryAdminGRPCConn)
		_, err = secCli.DeleteIdentity(ctx, &api.DeleteIdentityRequest{
			Id: createIdentity.Identity.Id, AppId: createApp.Id,
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
			createApp.Id)

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		createIdentity, err := aiCli.CreateIdentity(ctx,
			&api.CreateIdentityRequest{Identity: identity})
		t.Logf("createIdentity, err: %+v, %v", createIdentity, err)
		require.NoError(t, err)

		identityIDs = append(identityIDs, createIdentity.Identity.Id)
		identityComments = append(identityComments,
			createIdentity.Identity.Comment)
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
		require.GreaterOrEqual(t, len(listIdentities.Identities), 3)
		require.GreaterOrEqual(t, listIdentities.TotalSize, int32(3))

		var found bool
		for _, identity := range listIdentities.Identities {
			if identity.Id == identityIDs[len(identityIDs)-1] &&
				identity.Comment == identityComments[len(identityComments)-1] {
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
		require.Len(t, listIdentities.Identities, 2)
		require.NotEmpty(t, listIdentities.NextPageToken)
		require.GreaterOrEqual(t, listIdentities.TotalSize, int32(3))

		nextIdentities, err := aiCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{
				PageSize: 2, PageToken: listIdentities.NextPageToken,
			})
		t.Logf("nextIdentities, err: %+v, %v", nextIdentities, err)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(nextIdentities.Identities), 1)
		require.GreaterOrEqual(t, nextIdentities.TotalSize, int32(3))
	})

	t.Run("List identities with app filter", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		aiCli := api.NewAppIdentityServiceClient(globalAdminGRPCConn)
		listIdentities, err := aiCli.ListIdentities(ctx,
			&api.ListIdentitiesRequest{AppId: createApp.Id})
		t.Logf("listIdentities, err: %+v, %v", listIdentities, err)
		require.NoError(t, err)
		require.Len(t, listIdentities.Identities, 3)
		require.Equal(t, int32(3), listIdentities.TotalSize)

		var found bool
		for _, identity := range listIdentities.Identities {
			if identity.Id == identityIDs[len(identityIDs)-1] &&
				identity.Comment == identityComments[len(identityComments)-1] {
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
		require.Len(t, listIdentities.Identities, 0)
		require.Equal(t, int32(0), listIdentities.TotalSize)
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
