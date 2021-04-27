// +build !unit

package identity

import (
	"crypto/rand"
	"log"
	"os"
	"testing"

	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/dao/app"
	"github.com/ownmfa/hermes/pkg/dao/org"
	"github.com/ownmfa/hermes/pkg/test/config"
)

var (
	globalOrgDAO      *org.DAO
	globalAppDAO      *app.DAO
	globalIdentityDAO *DAO
)

func TestMain(m *testing.M) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("TestMain rand.Read: %v", err)
	}

	// Set up Config.
	testConfig := config.New()

	// Set up database connection.
	pg, err := dao.NewPgDB(testConfig.PgURI)
	if err != nil {
		log.Fatalf("TestMain dao.NewPgDB: %v", err)
	}
	globalOrgDAO = org.NewDAO(pg)
	globalAppDAO = app.NewDAO(pg)
	globalIdentityDAO = NewDAO(pg, key)

	os.Exit(m.Run())
}
