// +build !integration

package notifier

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/api/go/message"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/queue"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const errTestProc consterr.Error = "notifier: test processor error"

func TestNotifyMessages(t *testing.T) {
	t.Parallel()

	app := random.App("not", uuid.NewString())
	identity := random.SMSIdentity("not", app.OrgId, app.Id)
	traceID := uuid.New()

	knownKey, err := hex.DecodeString("b76c5da0d71b5646ed38b483532cded2622d07" +
		"2a5d175030b6540169b7380d58")
	require.NoError(t, err)

	tests := []struct {
		inpNIn      *message.NotifierIn
		inpExpire   time.Duration
		inpSMSTimes int
	}{
		{
			&message.NotifierIn{
				OrgId: app.OrgId, AppId: app.Id, IdentityId: identity.Id,
				TraceId: traceID[:],
			}, smsExpire, 1,
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
			identityer.EXPECT().Read(gomock.Any(), lTest.inpNIn.IdentityId,
				lTest.inpNIn.OrgId, lTest.inpNIn.AppId).Return(identity, otp,
				nil).Times(1)

			cacher := cache.NewMockCacher(ctrl)
			cacher.EXPECT().GetI(gomock.Any(), key.HOTPCounter(
				lTest.inpNIn.OrgId, lTest.inpNIn.AppId,
				lTest.inpNIn.IdentityId)).Return(true, int64(5), nil).Times(1)
			cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), key.Expire(
				lTest.inpNIn.OrgId, lTest.inpNIn.AppId, lTest.inpNIn.IdentityId,
				"861821"), 1, lTest.inpExpire).Return(true, nil).Times(1)

			apper := NewMockapper(ctrl)
			apper.EXPECT().Read(gomock.Any(), lTest.inpNIn.AppId,
				lTest.inpNIn.OrgId).Return(app, nil).Times(1)

			notifier := notify.NewMockNotifier(gomock.NewController(t))
			notifier.EXPECT().SMS(gomock.Any(), gomock.Any(), app.DisplayName,
				"861821").DoAndReturn(func(_ ...interface{}) error {
				defer wg.Done()

				return nil
			}).Times(lTest.inpSMSTimes)

			not := Notifier{
				appDAO:      apper,
				identityDAO: identityer,
				cache:       cacher,

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
	identity := random.SMSIdentity("not", app.OrgId, app.Id)

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
		inpGetIErr               error
		inpGetITimes             int
		inpOTP                   *oath.OTP
		inpAppErr                error
		inpAppTimes              int
		inpExpire                time.Duration
		inpSetIfNotExistTTLErr   error
		inpSetIfNotExistTTLTimes int
		inpSMSErr                error
		inpSMSTimes              int
		inpNotifyTimes           int
	}{
		// Bad payload.
		{
			nil, nil, nil, 0, nil, 0, nil, nil, 0, -1, nil, 0, nil, 0, 0,
		},
		// Identityer error.
		{
			&message.NotifierIn{}, identity, errTestProc, 1, nil, 0, nil, nil,
			0, -1, nil, 0, nil, 0, 0,
		},
		// Cacher GetI error.
		{
			&message.NotifierIn{}, identity, nil, 1, errTestProc, 1, nil, nil,
			0, -1, nil, 0, nil, 0, 0,
		},
		// OTP error.
		{
			&message.NotifierIn{}, identity, nil, 1, nil, 1, &oath.OTP{}, nil,
			0, -1, nil, 0, nil, 0, 0,
		},
		// Apper error.
		{
			&message.NotifierIn{}, identity, nil, 1, nil, 1, otp, errTestProc,
			1, -1, nil, 0, nil, 0, 0,
		},
		// Cacher SetIfNotExistTTL error.
		{
			&message.NotifierIn{}, identity, nil, 1, nil, 1, otp, nil, 1,
			smsExpire, errTestProc, 1, nil, 0, 0,
		},
		// Notifier SMS error.
		{
			&message.NotifierIn{}, identity, nil, 1, nil, 1, otp, nil, 1,
			smsExpire, nil, 1, errTestProc, 1, 1,
		},
		// Unsupported identity.MethodOneof.
		{
			&message.NotifierIn{}, random.HOTPIdentity("not", app.OrgId,
				app.Id), nil, 1, nil, 1, otp, nil, 1, smsExpire, nil, 0, nil, 0,
			0,
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
			cacher.EXPECT().GetI(gomock.Any(), gomock.Any()).Return(true,
				int64(5), lTest.inpGetIErr).Times(lTest.inpGetITimes)

			apper := NewMockapper(ctrl)
			apper.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(app, lTest.inpAppErr).Times(lTest.inpAppTimes)

			cacher.EXPECT().SetIfNotExistTTL(gomock.Any(), gomock.Any(), 1,
				lTest.inpExpire).Return(true, lTest.inpSetIfNotExistTTLErr).
				Times(lTest.inpSetIfNotExistTTLTimes)

			notifier := notify.NewMockNotifier(gomock.NewController(t))
			notifier.EXPECT().SMS(gomock.Any(), gomock.Any(), app.DisplayName,
				"861821").DoAndReturn(func(_ ...interface{}) error {
				defer wg.Done()

				return lTest.inpSMSErr
			}).Times(lTest.inpSMSTimes)

			not := Notifier{
				appDAO:      apper,
				identityDAO: identityer,
				cache:       cacher,

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
