// Package config provides configuration values and defaults for the API
// service.
package config

import "github.com/ownmfa/hermes/pkg/config"

const pref = "API_"

// Config holds settings used by the API service.
type Config struct {
	LogLevel   string
	StatsDAddr string

	PgURI     string
	RedisHost string

	PWTKey      []byte
	IdentityKey []byte

	NSQPubAddr  string
	NSQPubTopic string
}

// New instantiates a service Config, parses the environment, and returns it.
func New() *Config {
	return &Config{
		LogLevel:   config.String(pref+"LOG_LEVEL", "DEBUG"),
		StatsDAddr: config.String(pref+"STATSD_ADDR", ""),

		PgURI: config.String(pref+"PG_URI",
			"postgres://postgres:postgres@127.0.0.1/hermes_test"),
		RedisHost: config.String(pref+"REDIS_HOST", "127.0.0.1"),

		PWTKey:      config.ByteSlice(pref + "PWT_KEY"),
		IdentityKey: config.ByteSlice(pref + "IDENTITY_KEY"),

		NSQPubAddr:  config.String(pref+"NSQ_PUB_ADDR", "127.0.0.1:4150"),
		NSQPubTopic: config.String(pref+"NSQ_PUB_TOPIC", "ValidatorIn"),
	}
}
