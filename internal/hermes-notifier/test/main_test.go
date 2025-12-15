//go:build !unit

package test

import (
	"crypto/rand"
	"log"
	"os"
	"testing"

	"github.com/ownmfa/hermes/internal/hermes-notifier/config"
	"github.com/ownmfa/hermes/internal/hermes-notifier/notifier"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/dao/app"
	"github.com/ownmfa/hermes/pkg/dao/event"
	"github.com/ownmfa/hermes/pkg/dao/identity"
	"github.com/ownmfa/hermes/pkg/dao/org"
	"github.com/ownmfa/hermes/pkg/queue"
	testconfig "github.com/ownmfa/hermes/pkg/test/config"
	"github.com/ownmfa/hermes/pkg/test/random"
)

var (
	globalNInSubTopic string
	globalNotQueue    queue.Queuer

	globalOrgDAO   *org.DAO
	globalAppDAO   *app.DAO
	globalIdentDAO *identity.DAO
	globalEvDAO    *event.DAO
	globalCache    cache.Cacher[string]
)

func TestMain(m *testing.M) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("TestMain rand.Read: %v", err)
	}

	// Set up Config.
	testConfig := testconfig.New()
	cfg := config.New()
	cfg.PgRwURI = testConfig.PgURI
	cfg.PgRoURI = testConfig.PgURI
	cfg.RedisHost = testConfig.RedisHost

	cfg.IdentityKey = key

	cfg.NSQPubAddr = testConfig.NSQPubAddr
	cfg.NSQLookupAddrs = testConfig.NSQLookupAddrs
	cfg.NSQSubTopic += "-test-" + random.String(10)
	globalNInSubTopic = cfg.NSQSubTopic
	log.Printf("TestMain cfg.NSQSubTopic: %v", cfg.NSQSubTopic)
	// Use a unique channel for each test run. This prevents failed tests from
	// interfering with the next run, but does require eventual cleaning.
	cfg.NSQSubChannel = "notifier-test-" + random.String(10)

	// Set up NSQ queue to publish test payloads.
	var err error
	globalNotQueue, err = queue.NewNSQ(cfg.NSQPubAddr, nil, "")
	if err != nil {
		log.Fatalf("TestMain queue.NewNSQ: %v", err)
	}

	// Set up Notifier.
	ale, err := notifier.New(cfg)
	if err != nil {
		log.Fatalf("TestMain notifier.New: %v", err)
	}

	// Serve connections.
	go func() {
		ale.Serve(cfg.Concurrency)
	}()

	// Set up database connection.
	pg, err := dao.NewPgDB(cfg.PgRwURI)
	if err != nil {
		log.Fatalf("TestMain dao.NewPgDB: %v", err)
	}
	globalOrgDAO = org.NewDAO(pg, pg, nil, 0)
	globalAppDAO = app.NewDAO(pg, pg)
	globalIdentDAO = identity.NewDAO(pg, pg, key)
	globalEvDAO = event.NewDAO(pg, pg)

	// Set up cache connection.
	globalCache, err = cache.NewRedis[string](cfg.RedisHost + ":6379")
	if err != nil {
		log.Fatalf("TestMain cache.NewRedis: %v", err)
	}

	os.Exit(m.Run())
}
