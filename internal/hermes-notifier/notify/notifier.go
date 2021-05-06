// Package notify provides functions to send notifications.
package notify

//go:generate mockgen -source notifier.go -destination mock_notifier.go -package notify

import "context"

// Notifier defines the methods provided by a Notify.
type Notifier interface {
	// VaildateSMS verifies that a phone number is correct and supported for SMS
	// usage.
	VaildateSMS(ctx context.Context, phone string) error
	// SMS sends an SMS notification. This operation can block based on rate
	// limiting.
	SMS(ctx context.Context, phone, body string) error
	// Pushover sends a Pushover notification. This operation can block based on
	// rate limiting.
	Pushover(ctx context.Context, userKey, subject, body string) error
	// Email sends an email notification. The provider domain used for sending
	// is derived from the organization's email address: "mg." followed by the
	// domain name that follows '@' in the address. This operation can block
	// based on rate limiting.
	Email(ctx context.Context, displayName, appEmail, userEmail, subject,
		body string) error
}
