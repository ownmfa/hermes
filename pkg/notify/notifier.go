// Package notify provides functions to send notifications.
package notify

//go:generate mockgen -source notifier.go -destination mock_notifier.go -package notify

import "context"

// Notifier defines the methods provided by a Notify.
type Notifier interface {
	// ValidateSMS verifies that a phone number is correct and supported for SMS
	// usage.
	ValidateSMS(ctx context.Context, phone string) error
	// SMS sends an SMS verification. This operation can block based on rate
	// limiting.
	SMS(ctx context.Context, phone, displayName, passcode string) error
	// ValidatePushover verifies that a Pushover user key is valid.
	ValidatePushover(userKey string) error
	// Pushover sends a Pushover notification using the default application key
	// and templates. This operation can block based on rate limiting.
	Pushover(ctx context.Context, userKey, displayName, passcode string) error
	// PushoverByApp sends a Pushover notification by application key. This
	// operation can block based on rate limiting.
	PushoverByApp(ctx context.Context, appKey, userKey, subject,
		body string) error
	// Email sends an email notification. This operation can block based on rate
	// limiting.
	Email(ctx context.Context, displayName, from, to, subject, body,
		htmlBody string) error
}
