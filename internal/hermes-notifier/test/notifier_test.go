// +build !unit

package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/api/go/message"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const testTimeout = 8 * time.Second

func TestNotifyMessages(t *testing.T) {
	t.Parallel()

	traceID := uuid.New()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("not"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("not", createOrg.Id))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	createSMSIdentity, _, _, err := globalIdentityDAO.Create(ctx,
		random.SMSIdentity("not", createOrg.Id, createApp.Id))
	t.Logf("createSMSIdentity, err: %+v, %v", createSMSIdentity, err)
	require.NoError(t, err)

	tests := []struct {
		inp *message.NotifierIn
	}{
		{&message.NotifierIn{
			OrgId: createOrg.Id, AppId: createApp.Id,
			IdentityId: createSMSIdentity.Id, TraceId: traceID[:],
		}},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can notify %+v", lTest), func(t *testing.T) {
			t.Parallel()

			bNIn, err := proto.Marshal(lTest.inp)
			require.NoError(t, err)
			t.Logf("bNIn: %s", bNIn)

			require.NoError(t, globalNotQueue.Publish(globalNInSubTopic, bNIn))
			time.Sleep(time.Second)
		})
	}
}

func TestNotifyMessagesError(t *testing.T) {
	t.Parallel()

	traceID := uuid.New()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("not"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("not", createOrg.Id))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	badOTPIdentity := random.HOTPIdentity("not", createOrg.Id, createApp.Id)
	badOTPIdentity.MethodOneof = &api.Identity_HardwareHotpMethod{
		HardwareHotpMethod: &api.HardwareHOTPMethod{},
	}
	createBadOTPIdentity, _, _, err := globalIdentityDAO.Create(ctx,
		badOTPIdentity)
	require.NoError(t, err)

	createExpIdentity, otp, _, err := globalIdentityDAO.Create(ctx,
		random.SMSIdentity("not", createOrg.Id, createApp.Id))
	t.Logf("createExpIdentity, otp, err: %+v, %#v, %v", createExpIdentity, otp,
		err)
	require.NoError(t, err)

	passcode, err := otp.HOTP(1)
	require.NoError(t, err)

	ok, err := globalCache.SetIfNotExist(ctx, key.Expire(createOrg.Id,
		createApp.Id, createExpIdentity.Id, passcode), 1)
	require.True(t, ok)
	require.NoError(t, err)

	createUnsupIdentity, _, _, err := globalIdentityDAO.Create(ctx,
		random.HOTPIdentity("not", createOrg.Id, createApp.Id))
	t.Logf("createUnsupIdentity, err: %+v, %v", createUnsupIdentity, err)
	require.NoError(t, err)

	tests := []struct {
		inp *message.NotifierIn
	}{
		// Bad payload.
		{nil},
		// OTP error.
		{
			&message.NotifierIn{
				OrgId: createOrg.Id, AppId: createApp.Id,
				IdentityId: createBadOTPIdentity.Id, TraceId: traceID[:],
			},
		},
		// Expiration collision.
		{
			&message.NotifierIn{
				OrgId: createOrg.Id, AppId: createApp.Id,
				IdentityId: createExpIdentity.Id, TraceId: traceID[:],
			},
		},
		// Unsupported identity.MethodOneof.
		{
			&message.NotifierIn{
				OrgId: createOrg.Id, AppId: createApp.Id,
				IdentityId: createUnsupIdentity.Id, TraceId: traceID[:],
			},
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Cannot notify %+v", lTest), func(t *testing.T) {
			t.Parallel()

			bNIn := []byte("not-aaa")
			if lTest.inp != nil {
				var err error
				bNIn, err = proto.Marshal(lTest.inp)
				require.NoError(t, err)
				t.Logf("bNIn: %s", bNIn)
			}

			require.NoError(t, globalNotQueue.Publish(globalNInSubTopic, bNIn))
			time.Sleep(time.Second)
		})
	}
}
