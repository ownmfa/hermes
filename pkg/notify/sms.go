package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/ownmfa/hermes/pkg/consterr"
)

// ErrInvalidSMS is returned when a phone number fails validation for use.
const ErrInvalidSMS consterr.Error = "unknown or unsupported phone number"

// Constants used for the configuration of SMS notifications.
const (
	smsKey       = "notify.sms"
	smsRateDelay = 750 * time.Millisecond

	smsBodyTempl = "Your %s verification code is: %s. DO NOT share this " +
		"code. We will NOT contact you for it."
)

// VaildateSMS verifies that a phone number is correct and supported for SMS
// usage.
func (n *notify) VaildateSMS(ctx context.Context, phone string) error {
	lookup, err := n.twilio.lookupCarrier(ctx, phone)
	if err != nil {
		return err
	}

	if lookup.Carrier.Type != "mobile" && lookup.Carrier.Type != "voip" {
		return ErrInvalidSMS
	}

	return nil
}

// SMS sends an SMS verification. This operation can block based on rate
// limiting.
func (n *notify) SMS(ctx context.Context, phone, displayName,
	passcode string) error {
	// Support modified Twilio rate limit of 1 per second, serially. Twilio will
	// queue up to 4 hours worth of messages (14,400), but at the risk of abuse
	// by fraudulent users:
	// https://support.twilio.com/hc/en-us/articles/115002943027-Understanding-Twilio-Rate-Limits-and-Message-Queues
	ok, err := n.cache.SetIfNotExistTTL(ctx, smsKey, 1, smsRateDelay)
	if err != nil {
		return err
	}
	for !ok {
		time.Sleep(smsRateDelay)

		ok, err = n.cache.SetIfNotExistTTL(ctx, smsKey, 1, smsRateDelay)
		if err != nil {
			return err
		}
	}

	body := fmt.Sprintf(smsBodyTempl, displayName, passcode)
	err = n.twilio.sendSMS(ctx, phone, body)

	return err
}
