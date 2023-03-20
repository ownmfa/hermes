package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gregdel/pushover"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/metric"
)

// ErrInvalidPushover is returned when a user key fails validation.
const ErrInvalidPushover consterr.Error = "unknown user key"

const (
	poKey       = "notify.app"
	poRateDelay = 500 * time.Millisecond

	poSubjTempl = "%s verification code"
	poBodyTempl = "Your %s verification code is: %s. DO NOT share this code. " +
		"We will NOT contact you for it."
)

// VaildatePushover verifies that a Pushover user key is valid.
func (n *notify) VaildatePushover(userKey string) error {
	po := pushover.New(n.pushoverAppKey)
	recipient := pushover.NewRecipient(userKey)

	// GetRecipientDetails does not return sentinel errors via the API, return
	// ErrInvalidPushover based on status.
	det, err := po.GetRecipientDetails(recipient)
	if errors.Is(err, pushover.ErrInvalidRecipientToken) ||
		(det != nil && det.Status != 1) {
		return ErrInvalidPushover
	}
	if err != nil {
		return err
	}

	return nil
}

// Pushover sends a Pushover notification using the default application key and
// templates. This operation can block based on rate limiting.
func (n *notify) Pushover(
	ctx context.Context, userKey, displayName, passcode string,
) error {
	subj := fmt.Sprintf(poSubjTempl, displayName)
	body := fmt.Sprintf(poBodyTempl, displayName, passcode)

	return n.pushover(ctx, n.pushoverAppKey, userKey, subj, body)
}

// PushoverByApp sends a Pushover notification by application key. This
// operation can block based on rate limiting.
func (n *notify) PushoverByApp(
	ctx context.Context, appKey, userKey, subject, body string,
) error {
	return n.pushover(ctx, appKey, userKey, subject, body)
}

// pushover sends a Pushover notification by application key. This operation can
// block based on rate limiting.
func (n *notify) pushover(
	ctx context.Context, appKey, userKey, subject, body string,
) error {
	po := pushover.New(appKey)
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
	ok, err := n.cache.SetIfNotExistTTL(ctx, poKey, 1, poRateDelay)
	if err != nil {
		return err
	}
	for !ok {
		time.Sleep(poRateDelay)

		ok, err = n.cache.SetIfNotExistTTL(ctx, poKey, 1, poRateDelay)
		if err != nil {
			return err
		}
	}

	resp, err := po.SendMessage(msg, recipient)
	// Set remaining message limit if present, regardless of error.
	if resp != nil && resp.Limit != nil {
		metric.Set(poKey+".remaining", resp.Limit.Remaining, nil)
	}

	return err
}
