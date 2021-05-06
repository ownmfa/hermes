package notify

import "github.com/ownmfa/hermes/pkg/cache"

// notify contains methods to send notifications and implements the Notifier
// interface.
type notify struct {
	cache cache.Cacher

	smsAccountSID  string
	smsAuthToken   string
	smsPhone       string
	pushoverAPIKey string
	emailAPIKey    string
}

// Verify notify implements Notifier.
var _ Notifier = &notify{}

// New builds a new Notifier and returns it.
func New(cache cache.Cacher, smsAccountSID, smsAuthToken, smsPhone,
	pushoverAPIKey, emailAPIKey string) Notifier {
	return &notify{
		cache: cache,

		smsAccountSID:  smsAccountSID,
		smsAuthToken:   smsAuthToken,
		smsPhone:       smsPhone,
		pushoverAPIKey: pushoverAPIKey,
		emailAPIKey:    emailAPIKey,
	}
}