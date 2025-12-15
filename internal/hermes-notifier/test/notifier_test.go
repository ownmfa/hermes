//go:build !unit

package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/hermes/proto/go/message"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const testTimeout = 15 * time.Second

func TestNotifyMessages(t *testing.T) {
	t.Parallel()

	traceID := uuid.New()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("not"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	app := random.App("not", createOrg.GetId())
	app.PushoverKey = ""
	createApp, err := globalAppDAO.Create(ctx, app)
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	createSMSIdentity, _, _, err := globalIdentDAO.Create(ctx,
		random.SMSIdentity("not", createOrg.GetId(), createApp.GetId()))
	t.Logf("createSMSIdentity, err: %+v, %v", createSMSIdentity, err)
	require.NoError(t, err)

	createPushoverIdentity, _, _, err := globalIdentDAO.Create(ctx,
		random.PushoverIdentity("not", createOrg.GetId(), createApp.GetId()))
	t.Logf("createPushoverIdentity, err: %+v, %v", createPushoverIdentity, err)
	require.NoError(t, err)

	createEmailIdentity, _, _, err := globalIdentDAO.Create(ctx,
		random.EmailIdentity("not", createOrg.GetId(), createApp.GetId()))
	t.Logf("createEmailIdentity, err: %+v, %v", createEmailIdentity, err)
	require.NoError(t, err)

	appByKey := random.App("not", createOrg.GetId())
	appByKey.PushoverKey = random.String(30)
	createAppByKey, err := globalAppDAO.Create(ctx, appByKey)
	t.Logf("createAppByKey, err: %+v, %v", createAppByKey, err)
	require.NoError(t, err)

	createIdentityByKey, _, _, err := globalIdentDAO.Create(ctx,
		random.PushoverIdentity("not", createOrg.GetId(), createAppByKey.GetId()))
	t.Logf("createIdentityByKey, err: %+v, %v", createIdentityByKey, err)
	require.NoError(t, err)

	tests := []struct {
		inp *message.NotifierIn
	}{
		{
			&message.NotifierIn{
				OrgId: createOrg.GetId(), AppId: createApp.GetId(),
				IdentityId: createSMSIdentity.GetId(), TraceId: traceID[:],
			},
		},
		{
			&message.NotifierIn{
				OrgId: createOrg.GetId(), AppId: createApp.GetId(),
				IdentityId: createPushoverIdentity.GetId(), TraceId: traceID[:],
			},
		},
		{
			&message.NotifierIn{
				OrgId: createOrg.GetId(), AppId: createAppByKey.GetId(),
				IdentityId: createIdentityByKey.GetId(), TraceId: traceID[:],
			},
		},
		{
			&message.NotifierIn{
				OrgId: createOrg.GetId(), AppId: createApp.GetId(),
				IdentityId: createEmailIdentity.GetId(), TraceId: traceID[:],
			},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can notify %+v", test), func(t *testing.T) {
			t.Parallel()

			bNIn, err := proto.Marshal(test.inp)
			require.NoError(t, err)
			t.Logf("bNIn: %s", bNIn)

			require.NoError(t, globalNotQueue.Publish(globalNInSubTopic, bNIn))
			time.Sleep(2 * time.Second)

			// Verify event.
			event := &api.Event{
				OrgId:      test.inp.GetOrgId(),
				AppId:      test.inp.GetAppId(),
				IdentityId: test.inp.GetIdentityId(),
				Status:     api.EventStatus_CHALLENGE_SENT,
				TraceId:    traceID.String(),
			}

			ctx, cancel := context.WithTimeout(t.Context(),
				testTimeout)
			defer cancel()

			listEvents, err := globalEvDAO.List(ctx, test.inp.GetOrgId(),
				test.inp.GetIdentityId(), time.Now(), time.Now().
					Add(-testTimeout))
			t.Logf("listEvents, err: %+v, %v", listEvents, err)
			require.NoError(t, err)
			require.Len(t, listEvents, 1)

			// Normalize timestamp.
			require.WithinDuration(t, time.Now(),
				listEvents[0].GetCreatedAt().AsTime(), testTimeout)
			event.CreatedAt = listEvents[0].GetCreatedAt()

			require.EqualExportedValues(t, event, listEvents[0])
		})
	}
}

func TestNotifyMessagesError(t *testing.T) {
	t.Parallel()

	traceID := uuid.New()

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	createOrg, err := globalOrgDAO.Create(ctx, random.Org("not"))
	t.Logf("createOrg, err: %+v, %v", createOrg, err)
	require.NoError(t, err)

	createApp, err := globalAppDAO.Create(ctx, random.App("not",
		createOrg.GetId()))
	t.Logf("createApp, err: %+v, %v", createApp, err)
	require.NoError(t, err)

	badOTPIdentity := random.HOTPIdentity("not", createOrg.GetId(),
		createApp.GetId())
	badOTPIdentity.MethodOneof = &api.Identity_HardwareHotpMethod{
		HardwareHotpMethod: &api.HardwareHOTPMethod{},
	}
	createBadOTPIdentity, _, _, err := globalIdentDAO.Create(ctx,
		badOTPIdentity)
	require.NoError(t, err)

	createExpIdentity, otp, _, err := globalIdentDAO.Create(ctx,
		random.SMSIdentity("not", createOrg.GetId(), createApp.GetId()))
	t.Logf("createExpIdentity, otp, err: %+v, %#v, %v", createExpIdentity, otp,
		err)
	require.NoError(t, err)

	passcode, err := otp.HOTP(1)
	require.NoError(t, err)

	require.NoError(t, globalCache.SetIfNotExist(ctx, key.Expire(
		createOrg.GetId(), createApp.GetId(), createExpIdentity.GetId(),
		passcode), ""))

	badTemplApp := random.App("not", createOrg.GetId())
	badTemplApp.SubjectTemplate = `{{if`
	createBadTemplApp, err := globalAppDAO.Create(ctx, badTemplApp)
	t.Logf("createBadTemplApp, err: %+v, %v", createBadTemplApp, err)
	require.NoError(t, err)

	createBadTemplIdentity, _, _, err := globalIdentDAO.Create(ctx,
		random.PushoverIdentity("not", createOrg.GetId(),
			createBadTemplApp.GetId()))
	t.Logf("createBadTemplIdentity, err: %+v, %v", createBadTemplIdentity, err)
	require.NoError(t, err)

	tests := []struct {
		inpNIn      *message.NotifierIn
		inpEvent    bool
		inpEventErr string
	}{
		// Bad payload.
		{nil, false, ""},
		// OTP error.
		{
			&message.NotifierIn{
				OrgId: createOrg.GetId(), AppId: createApp.GetId(),
				IdentityId: createBadOTPIdentity.GetId(), TraceId: traceID[:],
			}, false, "",
		},
		// Expiration collision.
		{
			&message.NotifierIn{
				OrgId: createOrg.GetId(), AppId: createApp.GetId(),
				IdentityId: createExpIdentity.GetId(), TraceId: traceID[:],
			}, false, "",
		},
		// Templates error.
		{
			&message.NotifierIn{
				OrgId: createOrg.GetId(), AppId: createBadTemplApp.GetId(),
				IdentityId: createBadTemplIdentity.GetId(), TraceId: traceID[:],
			}, true, "template: template:1: unclosed action",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Cannot notify %+v", test), func(t *testing.T) {
			t.Parallel()

			bNIn := []byte("not-aaa")
			if test.inpNIn != nil {
				var err error
				bNIn, err = proto.Marshal(test.inpNIn)
				require.NoError(t, err)
				t.Logf("bNIn: %s", bNIn)
			}

			require.NoError(t, globalNotQueue.Publish(globalNInSubTopic, bNIn))

			if test.inpEvent {
				time.Sleep(2 * time.Second)

				// Verify event.
				event := &api.Event{
					OrgId:      test.inpNIn.GetOrgId(),
					AppId:      test.inpNIn.GetAppId(),
					IdentityId: test.inpNIn.GetIdentityId(),
					Status:     api.EventStatus_CHALLENGE_FAIL,
					Error:      test.inpEventErr,
					TraceId:    traceID.String(),
				}

				ctx, cancel := context.WithTimeout(t.Context(),
					testTimeout)
				defer cancel()

				listEvents, err := globalEvDAO.List(ctx, test.inpNIn.GetOrgId(),
					test.inpNIn.GetIdentityId(), time.Now(),
					time.Now().Add(-testTimeout))
				t.Logf("listEvents, err: %+v, %v", listEvents, err)
				require.NoError(t, err)
				require.Len(t, listEvents, 1)

				// Normalize timestamp.
				require.WithinDuration(t, time.Now(),
					listEvents[0].GetCreatedAt().AsTime(), testTimeout)
				event.CreatedAt = listEvents[0].GetCreatedAt()

				require.EqualExportedValues(t, event, listEvents[0])
			}
		})
	}
}
