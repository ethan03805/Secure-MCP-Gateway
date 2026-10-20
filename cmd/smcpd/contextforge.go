package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
)

// attachContextForge opens the ContextForge Connector (E-36) and registers
// its control API routes. A catalog that fails its checks is reported by
// the Connector and the elements report; it does not stop the Gateway.
// The probe of a local-entry import runs as an unconfined subprocess in
// the Standalone profile; with [runtime] sandbox = "podman" the import is
// refused until the sandboxed probe is wired (smcpctl package build
// --sandbox podman is the path there).
func attachContextForge(ctx context.Context, cfg *config.Config, pkgs *library.Runtime, a *app.App, log *slog.Logger) (*connector.Connector, error) {
	c, err := connector.New(connector.Options{Config: cfg, Library: pkgs.Library(), Recorder: a.Evidence,
		Interp: library.Interpreters(cfg), Version: backend.Version, Log: log, Confined: cfg.Runtime.Sandbox == "podman"})
	if err != nil {
		return nil, fmt.Errorf("contextforge connector: %w", err)
	}
	c.Start(ctx)
	c.RegisterRoutes(a.Admin)
	return c, nil
}
