package org

import "fmt"

// orgKey returns a cache key to support organization keys.
func orgKey(orgID string) string {
	return fmt.Sprintf("dao:org:%s", orgID)
}
