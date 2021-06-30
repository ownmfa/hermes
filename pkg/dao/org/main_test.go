// +build !unit

package org

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/test/config"
)

var (
	globalOrgDAO      *DAO
	globalOrgDAOCache *DAO
)

func TestMain(m *testing.M) {
	// Set up Config.
	testConfig := config.New()

	// Set up database connection.
	pg, err := dao.NewPgDB(testConfig.PgURI)
	if err != nil {
		log.Fatalf("TestMain dao.NewPgDB: %v", err)
	}
	globalOrgDAO = NewDAO(pg, nil, 0)
	globalOrgDAOCache = NewDAO(pg, cache.NewMemory(), time.Minute)

	os.Exit(m.Run())
}
