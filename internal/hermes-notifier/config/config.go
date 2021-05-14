// Package config provides configuration values and defaults for the Notifier
// service.
package config

import "github.com/ownmfa/hermes/pkg/config"

const pref = "NOTIFIER_"

// Config holds settings used by the Notifier service.
type Config struct {
	LogLevel    string
	StatsDAddr  string
	Concurrency int

	PgURI     string
	RedisHost string

	IdentityKey []byte

	NSQPubAddr     string
	NSQLookupAddrs []string
	NSQSubTopic    string
	NSQSubChannel  string

	SMSID          string
	SMSToken       string
	SMSPhone       string
	PushoverAPIKey string
	EmailAPIKey    string
}

// New instantiates a service Config, parses the environment, and returns it.
func New() *Config {
	return &Config{
		LogLevel:    config.String(pref+"LOG_LEVEL", "DEBUG"),
		StatsDAddr:  config.String(pref+"STATSD_ADDR", ""),
		Concurrency: config.Int(pref+"CONCURRENCY", 5),

		PgURI: config.String(pref+"PG_URI",
			"postgres://postgres:postgres@127.0.0.1/hermes_test"),
		RedisHost: config.String(pref+"REDIS_HOST", "127.0.0.1"),

		IdentityKey: config.ByteSlice(pref + "IDENTITY_KEY"),

		NSQPubAddr: config.String(pref+"NSQ_PUB_ADDR", "127.0.0.1:4150"),
		NSQLookupAddrs: config.StringSlice(pref+"NSQ_LOOKUP_ADDRS",
			[]string{"127.0.0.1:4161"}),
		NSQSubTopic:   config.String(pref+"NSQ_SUB_TOPIC", "NotifierIn"),
		NSQSubChannel: config.String(pref+"NSQ_SUB_CHANNEL", "notifier"),

		SMSID: config.String(pref+"SMS_ID",
			"AC64c88859fa04d39148ac34c18107f883"),
		SMSToken:       config.String(pref+"SMS_TOKEN", ""),
		SMSPhone:       config.String(pref+"SMS_PHONE", "+15122344592"),
		PushoverAPIKey: config.String(pref+"PUSHOVER_API_KEY", ""),
		EmailAPIKey:    config.String(pref+"EMAIL_API_KEY", ""),
	}
}
