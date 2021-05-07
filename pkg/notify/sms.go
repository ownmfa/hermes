package notify

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/kevinburke/twilio-go"
	"github.com/ownmfa/hermes/pkg/consterr"
)

const (
	ErrInvalidSMS consterr.Error = "unknown or unsupported phone number"
	smsKey                       = "notify.sms"
	smsRateDelay                 = 750 * time.Millisecond
)

// VaildateSMS verifies that a phone number is correct and supported for SMS
// usage.
func (n *notify) VaildateSMS(ctx context.Context, phone string) error {
	client := twilio.NewClient(n.smsSID, n.smsSecret, nil)

	lookup, err := client.LookupPhoneNumbers.Get(ctx, phone,
		url.Values{"Type": []string{"carrier"}})
	if err != nil {
		return err
	}
	if lookup == nil {
		return ErrInvalidSMS
	}

	if lookup.Carrier.Type != "mobile" && lookup.Carrier.Type != "voip" {
		return ErrInvalidSMS
	}

	return nil
}

// SMS sends an SMS notification. This operation can block based on rate
// limiting.
func (n *notify) SMS(ctx context.Context, phone, body string) error {
	client := twilio.NewClient(n.smsSID, n.smsSecret, nil)

	// Truncate to message limit:
	// https://www.twilio.com/docs/glossary/what-sms-character-limit
	if len(body) > 160 {
		body = fmt.Sprintf("%s...", body[:157])
	}

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

	_, err = client.Messages.SendMessage(n.smsPhone, phone, body, nil)

	return err
}
