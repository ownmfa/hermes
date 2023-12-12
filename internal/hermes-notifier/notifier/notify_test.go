//go:build !integration

package notifier

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/hermes/api/go/message"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/queue"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/ownmfa/proto/go/api"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
)

const errTestProc consterr.Error = "notifier: test processor error"

func TestNotifyMessages(t *testing.T) {
	t.Parallel()

	app := random.App("not", uuid.NewString())
	app.PushoverKey = ""
	smsIdentity := random.SMSIdentity("not", app.GetOrgId(), app.GetId())
	pushoverIdentity := random.PushoverIdentity("not", app.GetOrgId(), app.GetId())
	emailIdentity := random.EmailIdentity("not", app.GetOrgId(), app.GetId())
	traceID := uuid.New()

	appByKey := random.App("not", uuid.NewString())
	appByKey.PushoverKey = random.String(30)
	identityByKey := random.PushoverIdentity("not", appByKey.GetOrgId(), appByKey.GetId())

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	tests := []struct {
		inpNIn                *message.NotifierIn
		inpApp                *api.App
		inpIdentity           *api.Identity
		inpExpire             time.Duration
		inpSMSTimes           int
		inpPushoverTimes      int
		inpPushoverByAppTimes int
		inpEmailTimes         int
	}{
		{
			&message.NotifierIn{
				OrgId: app.GetOrgId(), AppId: app.GetId(), IdentityId: smsIdentity.GetId(),
				TraceId: traceID[:],
			}, app, smsIdentity, smsPushoverExpire, 1, 0, 0, 0,
		},
		{
			&message.NotifierIn{
				OrgId: app.GetOrgId(), AppId: app.GetId(),
				IdentityId: pushoverIdentity.GetId(), TraceId: traceID[:],
			}, app, pushoverIdentity, smsPushoverExpire, 0, 1, 0, 0,
		},
		{
			&message.NotifierIn{
				OrgId: appByKey.GetOrgId(), AppId: appByKey.GetId(),
				IdentityId: identityByKey.GetId(), TraceId: traceID[:],
			}, appByKey, identityByKey, smsPushoverExpire, 0, 0, 1, 0,
		},
		{
			&message.NotifierIn{
				OrgId: app.GetOrgId(), AppId: app.GetId(), IdentityId: emailIdentity.GetId(),
				TraceId: traceID[:],
			}, app, emailIdentity, emailExpire, 0, 0, 0, 1,
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can notify %+v", lTest), func(t *testing.T) {
			t.Parallel()

			nInQueue := queue.NewFake()
			nInSub, err := nInQueue.Subscribe("")
			require.NoError(t, err)

			var wg sync.WaitGroup
			wg.Add(1)

			otp := &oath.OTP{
				Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6,
				Key: knownKey,
			}

			ctrl := gomock.NewController(t)
			identityer := NewMockidentityer(ctrl)
			identityer.EXPECT().Read(gomock.Any(), lTest.inpNIn.GetIdentityId(),
				lTest.inpNIn.GetOrgId(), lTest.inpNIn.GetAppId()).
				Return(lTest.inpIdentity, otp, nil).Times(1)

			cacher := cache.NewMockCacher(ctrl)
			cacher.EXPECT().Incr(gomock.Any(), key.HOTPCounter(
				lTest.inpNIn.GetOrgId(), lTest.inpNIn.GetAppId(),
				lTest.inpNIn.GetIdentityId())).Return(int64(5), nil).Times(1)
			cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Expire(
				lTest.inpNIn.GetOrgId(), lTest.inpNIn.GetAppId(), lTest.inpNIn.GetIdentityId(),
				"861821"), 1, lTest.inpExpire).Return(true, nil).Times(1)

			apper := NewMockapper(ctrl)
			apper.EXPECT().Read(gomock.Any(), lTest.inpNIn.GetAppId(),
				lTest.inpNIn.GetOrgId()).Return(lTest.inpApp, nil).Times(1)

			notifier := notify.NewMockNotifier(ctrl)
			notifier.EXPECT().SMS(gomock.Any(),
				smsIdentity.GetSmsMethod().GetPhone(), lTest.inpApp.GetDisplayName(),
				"861821").Return(nil).Times(lTest.inpSMSTimes)
			notifier.EXPECT().Pushover(gomock.Any(),
				pushoverIdentity.GetPushoverMethod().GetPushoverKey(),
				lTest.inpApp.GetDisplayName(), "861821").Return(nil).
				Times(lTest.inpPushoverTimes)
			notifier.EXPECT().PushoverByApp(gomock.Any(),
				lTest.inpApp.GetPushoverKey(),
				identityByKey.GetPushoverMethod().GetPushoverKey(), gomock.Any(),
				gomock.Any()).Return(nil).Times(lTest.inpPushoverByAppTimes)
			notifier.EXPECT().Email(gomock.Any(), lTest.inpApp.GetDisplayName(),
				lTest.inpApp.GetEmail(), emailIdentity.GetEmailMethod().GetEmail(),
				gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).
				Times(lTest.inpEmailTimes)

			eventer := NewMockeventer(ctrl)
			eventer.EXPECT().Create(gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx interface{}, event interface{}) error {
					defer wg.Done()

					return nil
				}).Times(1)

			not := Notifier{
				appDAO:   apper,
				identDAO: identityer,
				evDAO:    eventer,
				cache:    cacher,

				notQueue: nInQueue,
				nInSub:   nInSub,

				notify: notifier,
			}
			go func() {
				not.notifyMessages()
			}()

			bNIn, err := proto.Marshal(lTest.inpNIn)
			require.NoError(t, err)
			t.Logf("bNIn: %s", bNIn)

			require.NoError(t, nInQueue.Publish("", bNIn))
			wg.Wait()
		})
	}
}

func TestNotifyMessagesError(t *testing.T) {
	t.Parallel()

	app := random.App("not", uuid.NewString())
	app.PushoverKey = ""
	smsIdentity := random.SMSIdentity("not", app.GetOrgId(), app.GetId())
	pushoverIdentity := random.PushoverIdentity("not", app.GetOrgId(), app.GetId())
	emailIdentity := random.EmailIdentity("not", app.GetOrgId(), app.GetId())

	badTemplApp := random.App("not", uuid.NewString())
	badTemplApp.SubjectTemplate = `{{if`

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	otp := &oath.OTP{
		Algorithm: oath.HOTP, Hash: crypto.SHA1, Digits: 6,
		Key: knownKey,
	}

	tests := []struct {
		inpNIn                   *message.NotifierIn
		inpIdentity              *api.Identity
		inpIdentityErr           error
		inpIdentityTimes         int
		inpIncrErr               error
		inpIncrTimes             int
		inpOTP                   *oath.OTP
		inpApp                   *api.App
		inpAppErr                error
		inpAppTimes              int
		inpExpire                time.Duration
		inpSetIfNotExistTTLErr   error
		inpSetIfNotExistTTLTimes int
		inpSMSErr                error
		inpSMSTimes              int
		inpPushoverErr           error
		inpPushoverTimes         int
		inpEmailErr              error
		inpEmailTimes            int
		inpNotifyTimes           int
	}{
		// Bad payload.
		{
			nil, nil, nil, 0, nil, 0, nil, nil, nil, 0, -1, nil, 0, nil, 0, nil,
			0, nil, 0, 0,
		},
		// Identityer error.
		{
			&message.NotifierIn{}, smsIdentity, errTestProc, 1, nil, 0, nil,
			nil, nil, 0, -1, nil, 0, nil, 0, nil, 0, nil, 0, 0,
		},
		// Cacher Incr error.
		{
			&message.NotifierIn{}, smsIdentity, nil, 1, errTestProc, 1, nil,
			nil, nil, 0, -1, nil, 0, nil, 0, nil, 0, nil, 0, 0,
		},
		// OTP error.
		{
			&message.NotifierIn{}, smsIdentity, nil, 1, nil, 1, &oath.OTP{},
			nil, nil, 0, -1, nil, 0, nil, 0, nil, 0, nil, 0, 0,
		},
		// Apper error.
		{
			&message.NotifierIn{}, smsIdentity, nil, 1, nil, 1, otp, nil,
			errTestProc, 1, -1, nil, 0, nil, 0, nil, 0, nil, 0, 0,
		},
		// Templates error.
		{
			&message.NotifierIn{}, pushoverIdentity, nil, 1, nil, 1, otp,
			badTemplApp, nil, 1, -1, nil, 0, nil, 0, nil, 0, nil, 0, 0,
		},
		// Cacher SetIfNotExistTTL error.
		{
			&message.NotifierIn{}, smsIdentity, nil, 1, nil, 1, otp, app, nil,
			1, smsPushoverExpire, errTestProc, 1, nil, 0, nil, 0, nil, 0, 0,
		},
		// Notifier SMS error.
		{
			&message.NotifierIn{}, smsIdentity, nil, 1, nil, 1, otp, app, nil,
			1, smsPushoverExpire, nil, 1, errTestProc, 1, nil, 0, nil, 0, 1,
		},
		// Notifier Pushover error.
		{
			&message.NotifierIn{}, pushoverIdentity, nil, 1, nil, 1, otp, app,
			nil, 1, smsPushoverExpire, nil, 1, nil, 0, errTestProc, 1, nil, 0, 1,
		},
		// Notifier email error.
		{
			&message.NotifierIn{}, emailIdentity, nil, 1, nil, 1, otp, app, nil,
			1, emailExpire, nil, 1, nil, 0, nil, 0, errTestProc, 1, 1,
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can notify %+v", lTest), func(t *testing.T) {
			t.Parallel()

			nInQueue := queue.NewFake()
			nInSub, err := nInQueue.Subscribe("")
			require.NoError(t, err)

			var wg sync.WaitGroup
			wg.Add(1)

			ctrl := gomock.NewController(t)
			identityer := NewMockidentityer(ctrl)
			identityer.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any()).Return(lTest.inpIdentity, lTest.inpOTP,
				lTest.inpIdentityErr).Times(lTest.inpIdentityTimes)

			cacher := cache.NewMockCacher(ctrl)
			cacher.EXPECT().Incr(gomock.Any(), gomock.Any()).Return(int64(5),
				lTest.inpIncrErr).Times(lTest.inpIncrTimes)

			apper := NewMockapper(ctrl)
			apper.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(lTest.inpApp, lTest.inpAppErr).Times(lTest.inpAppTimes)

			cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), gomock.Any(), 1,
				lTest.inpExpire).Return(true, lTest.inpSetIfNotExistTTLErr).
				Times(lTest.inpSetIfNotExistTTLTimes)

			notifier := notify.NewMockNotifier(ctrl)
			notifier.EXPECT().SMS(gomock.Any(),
				smsIdentity.GetSmsMethod().GetPhone(), app.GetDisplayName(), "861821").
				DoAndReturn(func(
					ctx interface{}, phone interface{}, displayName interface{},
					passcode interface{},
				) error {
					defer wg.Done()

					return lTest.inpSMSErr
				}).Times(lTest.inpSMSTimes)
			notifier.EXPECT().Pushover(gomock.Any(),
				pushoverIdentity.GetPushoverMethod().GetPushoverKey(),
				app.GetDisplayName(), "861821").DoAndReturn(func(
				ctx interface{}, userKey interface{}, displayName interface{},
				passcode interface{},
			) error {
				defer wg.Done()

				return lTest.inpPushoverErr
			}).Times(lTest.inpPushoverTimes)
			notifier.EXPECT().Email(gomock.Any(), app.GetDisplayName(), app.GetEmail(),
				emailIdentity.GetEmailMethod().GetEmail(), gomock.Any(),
				gomock.Any(), gomock.Any()).DoAndReturn(func(
				ctx interface{}, displayName interface{}, from interface{},
				to interface{}, subject interface{}, body interface{},
				htmlBody interface{},
			) error {
				defer wg.Done()

				return lTest.inpEmailErr
			}).Times(lTest.inpEmailTimes)

			eventer := NewMockeventer(ctrl)
			eventer.EXPECT().Create(gomock.Any(), gomock.Any()).
				Return(errTestProc).AnyTimes()

			not := Notifier{
				appDAO:   apper,
				identDAO: identityer,
				evDAO:    eventer,
				cache:    cacher,

				notQueue: nInQueue,
				nInSub:   nInSub,

				notify: notifier,
			}
			go func() {
				not.notifyMessages()
			}()

			bNIn := []byte("not-aaa")
			if lTest.inpNIn != nil {
				bNIn, err = proto.Marshal(lTest.inpNIn)
				require.NoError(t, err)
				t.Logf("bNIn: %s", bNIn)
			}

			require.NoError(t, nInQueue.Publish("", bNIn))
			if lTest.inpNotifyTimes > 0 {
				wg.Wait()
			} else {
				// If the success mode isn't supported by WaitGroup operation,
				// give it time to traverse the code.
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}

func TestGenTemplates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		inpApp      *api.App
		inpPasscode string
		resSubj     string
		resBody     string
		resHTMLBody string
		err         string
	}{
		{
			&api.App{}, "", "", "", "", "",
		},
		{
			&api.App{SubjectTemplate: `{{if`}, "", "", "", "",
			"unclosed action",
		},
		{
			&api.App{TextBodyTemplate: `{{if`}, "", "", "", "",
			"unclosed action",
		},
		{
			&api.App{HtmlBodyTemplate: []byte(`{{if`)}, "", "", "", "",
			"unclosed action",
		},
	}

	for _, test := range tests {
		lTest := test

		t.Run(fmt.Sprintf("Can generate %+v", lTest), func(t *testing.T) {
			t.Parallel()

			subj, body, htmlBody, err := genTemplates(lTest.inpApp,
				lTest.inpPasscode)
			t.Logf("subj, body, htmlBody, err: %v, %v, %v, %v", subj, body,
				htmlBody, err)
			require.Equal(t, lTest.resSubj, subj)
			require.Equal(t, lTest.resBody, body)
			require.Equal(t, lTest.resHTMLBody, htmlBody)
			if lTest.err == "" {
				require.NoError(t, err)
			} else {
				require.Contains(t, err.Error(), lTest.err)
			}
		})
	}
}
