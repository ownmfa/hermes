// Package config provides configuration values and defaults for the API
// service.
package config

import "github.com/ownmfa/hermes/pkg/config"

const pref = "API_"

// Config holds settings used by the API service.
type Config struct {
	LogLevel   string
	StatsDAddr string

	PgRwURI   string
	PgRoURI   string
	RedisHost string

	NSQPubAddr  string
	NSQPubTopic string

	SMSKeyID       string
	SMSKeySecret   string
	PushoverAPIKey string

	PWTKey      []byte
	IdentityKey []byte
	APIHost     string
}

// New instantiates a service Config, parses the environment, and returns it.
func New() *Config {
	return &Config{
		LogLevel:   config.String(pref+"LOG_LEVEL", "DEBUG"),
		StatsDAddr: config.String(pref+"STATSD_ADDR", ""),

		PgRwURI: config.String(pref+"PG_RW_URI",
			"postgres://postgres:postgres@127.0.0.1/hermes_test"),
		PgRoURI: config.String(pref+"PG_RO_URI",
			"postgres://postgres:postgres@127.0.0.1/hermes_test"),
		RedisHost: config.String(pref+"REDIS_HOST", "127.0.0.1"),

		NSQPubAddr:  config.String(pref+"NSQ_PUB_ADDR", "127.0.0.1:4150"),
		NSQPubTopic: config.String(pref+"NSQ_PUB_TOPIC", "NotifierIn"),

		SMSKeyID: config.String(pref+"SMS_KEY_ID",
			"SKc8b34a092fe8790061c58b3fb3db752f"),
		SMSKeySecret:   config.String(pref+"SMS_KEY_SECRET", ""),
		PushoverAPIKey: config.String(pref+"PUSHOVER_API_KEY", ""),

		PWTKey:      config.ByteSlice(pref + "PWT_KEY"),
		IdentityKey: config.ByteSlice(pref + "IDENTITY_KEY"),
		APIHost:     config.String(pref+"API_HOST", ""),
	}
}
