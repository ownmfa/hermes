// Package main starts the Notifier service.
package main

import (
	"github.com/ownmfa/hermes/internal/hermes-notifier/config"
	"github.com/ownmfa/hermes/internal/hermes-notifier/notifier"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/metric"
)

func main() {
	cfg := config.New()

	hlog.SetDefault(hlog.NewJSON().WithLevel(cfg.LogLevel).WithStr("service",
		notifier.ServiceName))
	metric.SetStatsD(cfg.StatsDAddr, notifier.ServiceName)

	// Build Notifier.
	not, err := notifier.New(cfg)
	if err != nil {
		hlog.Fatalf("main notifier.New: %v", err)
	}

	// Serve connections.
	not.Serve(cfg.Concurrency)
}
