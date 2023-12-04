// Package notifier provides functions used to run the Notifier service.
package notifier

//go:generate mockgen -source notifier.go -destination mock_apper_test.go -package notifier

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/internal/hermes-notifier/config"
	"github.com/ownmfa/hermes/pkg/cache"
	"github.com/ownmfa/hermes/pkg/consterr"
	"github.com/ownmfa/hermes/pkg/dao"
	"github.com/ownmfa/hermes/pkg/dao/app"
	"github.com/ownmfa/hermes/pkg/dao/event"
	"github.com/ownmfa/hermes/pkg/dao/identity"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/notify"
	"github.com/ownmfa/hermes/pkg/oath"
	"github.com/ownmfa/hermes/pkg/queue"
)

// ServiceName provides consistent naming, including logs and metrics.
const ServiceName = "notifier"

// errIdentityLength is returned due to insufficient key length.
const errIdentityLength consterr.Error = "identity key must be 32 bytes"

// apper defines the methods provided by an app.DAO.
type apper interface {
	Read(ctx context.Context, appID, orgID string) (*api.App, error)
}

// identityer defines the methods provided by an identity.DAO.
type identityer interface {
	Read(ctx context.Context, identityID, orgID, appID string) (*api.Identity,
		*oath.OTP, error)
}

// eventer defines the methods provided by a event.DAO.
type eventer interface {
	Create(ctx context.Context, event *api.Event) error
}

// Notifier holds references to the database and message broker connections.
type Notifier struct {
	appDAO   apper
	identDAO identityer
	evDAO    eventer
	cache    cache.Cacher

	notQueue queue.Queuer
	nInSub   queue.Subber

	notify notify.Notifier
}

// New builds a new Notifier and returns a reference to it and an error value.
func New(cfg *config.Config) (*Notifier, error) {
	// Validate Config.
	if len(cfg.IdentityKey) != 32 {
		return nil, errIdentityLength
	}

	// Set up database connection.
	pgRW, err := dao.NewPgDB(cfg.PgRwURI)
	if err != nil {
		return nil, err
	}

	pgRO, err := dao.NewPgDB(cfg.PgRoURI)
	if err != nil {
		return nil, err
	}

	// Set up cache connection.
	redis, err := cache.NewRedis(cfg.RedisHost + ":6379")
	if err != nil {
		return nil, err
	}

	// Set up Notifier. Allow a mock for local usage, but warn loudly.
	var n notify.Notifier
	if cfg.SMSKeySecret == "" || cfg.PushoverAPIKey == "" ||
		cfg.EmailAPIKey == "" {
		hlog.Error("New notify secrets not found, using notify.NewFake()")
		n = notify.NewFake()
	} else {
		n = notify.New(redis, cfg.SMSKeyID, cfg.SMSAccountID, cfg.SMSKeySecret,
			cfg.SMSPhone, cfg.PushoverAPIKey, cfg.EmailDomain, cfg.EmailAPIKey)
	}

	// Build the NSQ connection for consuming.
	nsq, err := queue.NewNSQ(cfg.NSQPubAddr, cfg.NSQLookupAddrs,
		cfg.NSQSubChannel)
	if err != nil {
		return nil, err
	}

	// Prime the queue before subscribing to allow for discovery by nsqlookupd.
	if err = nsq.Prime(cfg.NSQSubTopic); err != nil {
		return nil, err
	}

	// Subscribe to the topic.
	nInSub, err := nsq.Subscribe(cfg.NSQSubTopic)
	if err != nil {
		return nil, err
	}

	return &Notifier{
		appDAO:   app.NewDAO(pgRW, pgRO),
		identDAO: identity.NewDAO(pgRW, pgRO, cfg.IdentityKey),
		evDAO:    event.NewDAO(pgRW, pgRO),
		cache:    redis,

		notQueue: nsq,
		nInSub:   nInSub,

		notify: n,
	}, nil
}

// Serve starts the message notifiers.
func (not *Notifier) Serve(concurrency int) {
	for i := 0; i < concurrency; i++ {
		go not.notifyMessages()
	}

	// Handle graceful shutdown.
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, syscall.SIGINT, syscall.SIGTERM)
	<-exitChan

	hlog.Info("Serve received signal, exiting")
	if err := not.nInSub.Unsubscribe(); err != nil {
		hlog.Errorf("Serve not.nInSub.Unsubscribe: %v", err)
	}
	not.notQueue.Disconnect()
}
