// Command smcpd is the Secure MCP Gateway daemon: the harness listener with
// OAuth 2.1 sessions, policy decisions, dispatch to stdio MCP servers, the
// signed evidence journal and the loopback control API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
)

func main() {
	cfgPath := flag.String("config", "smcp.toml", "configuration file (TOML)")
	logLevel := flag.String("log-level", "", "diagnostic log level (debug, info, warn, error); overrides [log] level")
	flag.Parse()
	if err := run(*cfgPath, *logLevel); err != nil {
		fmt.Fprintln(os.Stderr, "smcpd:", err)
		os.Exit(1)
	}
}

func run(cfgPath, level string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if level == "" {
		level = cfg.Log.Level
	}
	log, _, err := diag.New(os.Stderr, level, cfg.Log.Format)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.Start(ctx, cfg, app.Options{Log: log})
	if err != nil {
		return err
	}
	defer a.Close()
	if err := a.Listen(); err != nil {
		return err
	}
	log.Info("smcpd listening", "mcp", cfg.ResourceURI(), "admin", cfg.AdminURL(), "policy_revision", a.Decider.Snapshot().Revision,
		"profile", a.Profile.Profile, "release_label", a.Profile.Label)
	err = a.Serve(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
