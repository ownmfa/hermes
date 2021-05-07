package notify

import "github.com/ownmfa/hermes/pkg/cache"

// notify contains methods to send notifications and implements the Notifier
// interface.
type notify struct {
	cache cache.Cacher

	smsSID         string
	smsSecret      string
	smsPhone       string
	pushoverAPIKey string
	emailAPIKey    string
}

// Verify notify implements Notifier.
var _ Notifier = &notify{}

// New builds a new Notifier and returns it.
func New(cache cache.Cacher, smsSID, smsSecret, smsPhone, pushoverAPIKey,
	emailAPIKey string) Notifier {
	return &notify{
		cache: cache,

		smsSID:         smsSID,
		smsSecret:      smsSecret,
		smsPhone:       smsPhone,
		pushoverAPIKey: pushoverAPIKey,
		emailAPIKey:    emailAPIKey,
	}
}
