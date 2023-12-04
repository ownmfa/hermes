// Package identity provides functions to create and query identities in the
// database.
package identity

import (
	"database/sql"
)

// DAO contains functions to create and query identities in the database.
type DAO struct {
	rw *sql.DB
	ro *sql.DB

	secretKey []byte
}

// NewDAO instantiates and returns a new DAO.
func NewDAO(rw *sql.DB, ro *sql.DB, secretKey []byte) *DAO {
	return &DAO{
		rw: rw,
		ro: ro,

		secretKey: secretKey,
	}
}
