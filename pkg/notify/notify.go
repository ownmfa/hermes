package notify

import "github.com/ownmfa/hermes/pkg/cache"

// notify contains methods to send notifications and implements the Notifier
// interface.
type notify struct {
	cache cache.Cacher

	twilio         *twilio
	pushoverAppKey string
	mailgun        *mailgun
}

// Verify notify implements Notifier.
var _ Notifier = &notify{}

// New builds a new Notifier and returns it.
func New(cache cache.Cacher, smsKeyID, smsAccountID, smsKeySecret, smsPhone,
	pushoverAppKey, emailDomain, emailAPIKey string) Notifier {
	return &notify{
		cache: cache,

		twilio: &twilio{
			keySID:     smsKeyID,
			accountSID: smsAccountID,
			keySecret:  smsKeySecret,
			phone:      smsPhone,
		},
		pushoverAppKey: pushoverAppKey,
		mailgun: &mailgun{
			domain: emailDomain,
			apiKey: emailAPIKey,
		},
	}
}
