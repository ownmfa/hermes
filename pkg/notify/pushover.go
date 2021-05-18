package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/gregdel/pushover"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/metric"
)

// ErrInvalidPushover is returned when a user key fails validation.
const ErrInvalidPushover consterr.Error = "unknown user key"

const (
	appKey       = "notify.app"
	appRateDelay = 500 * time.Millisecond
)

// VaildatePushover verifies that a Pushover user key is valid.
func (n *notify) VaildatePushover(ctx context.Context, userKey string) error {
	po := pushover.New(n.pushoverAPIKey)
	recipient := pushover.NewRecipient(userKey)

	// GetRecipientDetails is not returning a sentinel error as described,
	// return ErrInvalidPushover based on status.
	det, err := po.GetRecipientDetails(recipient)
	if det != nil && det.Status != 1 {
		return ErrInvalidPushover
	}
	if err != nil {
		return err
	}

	return nil
}

// Pushover sends a Pushover notification. This operation can block based on
// rate limiting.
func (n *notify) Pushover(ctx context.Context, userKey, subject,
	body string) error {
	po := pushover.New(n.pushoverAPIKey)
	recipient := pushover.NewRecipient(userKey)

	// Truncate to subject and body limits: https://pushover.net/api#limits
	if len(subject) > 250 {
		subject = fmt.Sprintf("%s...", subject[:247])
	}
	if len(body) > 1024 {
		body = fmt.Sprintf("%s...", body[:1024])
	}
	msg := pushover.NewMessageWithTitle(body, subject)

	// Support modified Pushover rate limit of 2 per second, serially:
	// https://pushover.net/api#friendly
	ok, err := n.cache.SetIfNotExistTTL(ctx, appKey, 1, appRateDelay)
	if err != nil {
		return err
	}
	for !ok {
		time.Sleep(appRateDelay)

		ok, err = n.cache.SetIfNotExistTTL(ctx, appKey, 1, appRateDelay)
		if err != nil {
			return err
		}
	}

	resp, err := po.SendMessage(msg, recipient)
	// Set remaining message limit if present, regardless of error.
	if resp != nil && resp.Limit != nil {
		metric.Set(appKey+".remaining", resp.Limit.Remaining, nil)
	}

	return err
}
