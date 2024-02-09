package org

// orgKey returns a cache key by organization ID.
func orgKey(orgID string) string {
	return "dao:org:" + orgID
}
