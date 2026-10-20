package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// openContextForge creates the ContextForge Connector (E-36) before the
// Gateway starts, so that enabled hosted packages resolve through it at the
// first launch. A catalog that fails its checks is reported by the
// Connector and the elements report; it does not stop the Gateway. The
// probe of a local-entry import runs as an unconfined subprocess in the
// Standalone profile; with [runtime] sandbox = "podman" the import is
// refused until the sandboxed probe is wired (smcpctl package build
// --sandbox podman is the path there).
func openContextForge(cfg *config.Config, pkgs *library.Runtime, sec *secrets.Service, confined bool, log *slog.Logger) (*connector.Connector, error) {
	var broker *secrets.Broker
	if sec != nil {
		broker = sec.Broker
	}
	c, err := connector.New(connector.Options{Config: cfg, Library: pkgs.Library(), Broker: broker, Suspend: pkgs.SuspendRevision,
		Enforced: confined, Interp: library.Interpreters(cfg), Version: backend.Version, Log: log,
		Confined: cfg.Runtime.Sandbox == "podman"})
	if err != nil {
		return nil, fmt.Errorf("contextforge connector: %w", err)
	}
	pkgs.SetHosted(c.ResolveHosted)
	return c, nil
}

// attachContextForge gives the started Gateway's journal, control API and
// health monitor to the Connector.
func attachContextForge(ctx context.Context, c *connector.Connector, a *app.App, mon *health.Monitor) {
	c.SetRecorder(a.Evidence)
	a.Evidence.AddDecorator(c.Decorate) // FR-22.39: route fields of hosted calls
	if p := c.ManagedProcess(); p != nil && runtime.GOOS == "windows" {
		// FR-22.25: the managed process in its Job Object is unconfined.
		mon.Register("contextforge-process", winsandbox.ContextForgeUnconfinedCheck(p.Running))
	}
	c.Start(ctx)
	c.RegisterRoutes(a.Admin)
	// FR-22.25, FR-22.30: degraded, never fail-closed, for the bundled
	// instance.
	mon.Register("contextforge", health.Every(10*time.Second, func(time.Time) []health.Cause {
		var out []health.Cause
		for name, detail := range c.HealthCauses() {
			out = append(out, health.Cause{Name: name, Detail: detail})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}))
}
