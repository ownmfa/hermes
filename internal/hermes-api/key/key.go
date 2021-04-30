// Package key provides functions to generate cache keys.
package key

import "fmt"

// Disabled returns a cache key to support disabled API keys.
func Disabled(orgID, keyID string) string {
	return fmt.Sprintf("api:disabled:org:%s:key:%s", orgID, keyID)
}

// HOTPCounter returns a cache key to retrieve the current HOTP counter.
func HOTPCounter(orgID, appID, identityID string) string {
	return fmt.Sprintf("api:hotpcounter:org:%s:app:%s:identity:%s", orgID,
		appID, identityID)
}

// TOTPOffset returns a cache key to retrieve the TOTP window offset.
func TOTPOffset(orgID, appID, identityID string) string {
	return fmt.Sprintf("api:totpoffset:org:%s:app:%s:identity:%s", orgID,
		appID, identityID)
}
