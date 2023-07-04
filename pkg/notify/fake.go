package notify

import (
	"github.com/ownmfa/hermes/pkg/hlog"
	"go.uber.org/mock/gomock"
)

// NewFake builds a new Notifier using a mock and returns it. It may be used in
// place of a Notify implementation, but should be accompanied by a warning.
func NewFake() Notifier {
	// Controller.Finish() is not called because usage is expected to be
	// long-lived.
	notifier := NewMockNotifier(gomock.NewController(hlog.Default()))
	notifier.EXPECT().ValidateSMS(gomock.Any(), gomock.Any()).Return(nil).
		AnyTimes()
	notifier.EXPECT().SMS(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Return(nil).AnyTimes()
	notifier.EXPECT().ValidatePushover(gomock.Any()).Return(nil).AnyTimes()
	notifier.EXPECT().Pushover(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Return(nil).AnyTimes()
	notifier.EXPECT().PushoverByApp(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	notifier.EXPECT().Email(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).
		AnyTimes()

	return notifier
}
