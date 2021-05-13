// Package key provides functions to generate cache keys.
package key

import "fmt"

// HOTPCounter returns a cache key to retrieve the current HOTP counter.
func HOTPCounter(orgID, appID, identityID string) string {
	return fmt.Sprintf("api_notifier:hotpcounter:org:%s:app:%s:identity:%s",
		orgID, appID, identityID)
}

// Expire returns a cache key to support passcode expiration.
func Expire(orgID, appID, identityID, passcode string) string {
	return fmt.Sprintf("api_notifier:expire:org:%s:app:%s:identity:%s:"+
		"passcode:%s", orgID, appID, identityID, passcode)
}
