//go:build !unit

package app

import (
	"log"
	"os"
	"testing"

	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/dao/org"
	"github.com/ownmfa/hermes/pkg/test/config"
)

var (
	globalOrgDAO *org.DAO
	globalAppDAO *DAO
)

func TestMain(m *testing.M) {
	// Set up Config.
	testConfig := config.New()

	// Set up database connection.
	pg, err := dao.NewPgDB(testConfig.PgURI)
	if err != nil {
		log.Fatalf("TestMain dao.NewPgDB: %v", err)
	}
	globalOrgDAO = org.NewDAO(pg, pg, nil, 0)
	globalAppDAO = NewDAO(pg, pg)

	os.Exit(m.Run())
}
