package main

import (
	"github.com/ownmfa/hermes/internal/api/api"
	"github.com/ownmfa/hermes/internal/api/config"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/metric"
)

func main() {
	cfg := config.New()

	hlog.SetDefault(hlog.NewJSON().WithLevel(cfg.LogLevel).WithStr("service",
		api.ServiceName))
	metric.SetStatsD(cfg.StatsDAddr, api.ServiceName)

	// Build API.
	a, err := api.New(cfg)
	if err != nil {
		hlog.Fatalf("main api.New: %v", err)
	}

	// Serve connections.
	a.Serve()
}
