// Package org provides functions to query and modify organizations in the
// database.
package org

import (
	"database/sql"
	"time"

	"github.com/ownmfa/hermes/pkg/cache"
)

// DAO contains functions to query and modify organizations in the database.
type DAO struct {
	pg    *sql.DB
	cache cache.Cacher
	exp   time.Duration
}

// NewDAO instantiates and returns a new DAO with organization read caching.
// Cache can be set to nil to disable caching.
func NewDAO(pg *sql.DB, cache cache.Cacher, exp time.Duration) *DAO {
	return &DAO{
		pg:    pg,
		cache: cache,
		exp:   exp,
	}
}
