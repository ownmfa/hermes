package org

import "fmt"

// orgKey returns a cache key by organization ID.
func orgKey(orgID string) string {
	return fmt.Sprintf("dao:org:%s", orgID)
}
