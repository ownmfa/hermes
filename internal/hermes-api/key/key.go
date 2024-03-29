// Package key provides functions to generate cache keys.
package key

import "fmt"

// Disabled returns a cache key to support disabled API keys.
func Disabled(orgID, keyID string) string {
	return fmt.Sprintf("api:disabled:org:%s:key:%s", orgID, keyID)
}

// TOTPOffset returns a cache key to retrieve the TOTP window offset.
func TOTPOffset(orgID, appID, identityID string) string {
	return fmt.Sprintf("api:totpoffset:org:%s:app:%s:identity:%s", orgID,
		appID, identityID)
}

// Reuse returns a cache key to support disallowing passcode reuse.
func Reuse(orgID, appID, identityID, passcode string) string {
	return fmt.Sprintf("api:reuse:org:%s:app:%s:identity:%s:passcode:%s", orgID,
		appID, identityID, passcode)
}

// Challenge returns a cache key to support rate limiting notifications.
func Challenge(orgID, appID, identityID string) string {
	return fmt.Sprintf("api:challenge:org:%s:app:%s:identity:%s", orgID, appID,
		identityID)
}
