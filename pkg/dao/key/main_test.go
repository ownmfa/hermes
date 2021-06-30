// +build !unit

package key

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
	globalKeyDAO *DAO
)

func TestMain(m *testing.M) {
	// Set up Config.
	testConfig := config.New()

	// Set up database connection.
	pg, err := dao.NewPgDB(testConfig.PgURI)
	if err != nil {
		log.Fatalf("TestMain dao.NewPgDB: %v", err)
	}
	globalOrgDAO = org.NewDAO(pg, nil, 0)
	globalKeyDAO = NewDAO(pg)

	os.Exit(m.Run())
}
