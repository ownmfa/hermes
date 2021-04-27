// Package identity provides functions to create and query identities in the
// database.
package identity

import (
	"database/sql"
)

// DAO contains functions to create and query identities in the database.
type DAO struct {
	pg *sql.DB

	secretKey []byte
}

// NewDAO instantiates and returns a new DAO.
func NewDAO(pg *sql.DB, secretKey []byte) *DAO {
	return &DAO{
		pg: pg,

		secretKey: secretKey,
	}
}
