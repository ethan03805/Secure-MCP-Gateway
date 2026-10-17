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

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
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

	// E-15/E-16/E-17: the confining launcher when [runtime] sandbox = "podman".
	rt, err := sandbox.FromConfig(ctx, cfg, sandbox.SetupOptions{Log: log})
	if err != nil {
		return err
	}
	approvals, err := approval.New(approval.Options{Config: cfg, Log: log}) // E-07
	if err != nil {
		return fmt.Errorf("approvals: %w", err)
	}
	defer approvals.Close()
	opts := app.Options{Log: log, Approver: approvals, Approvals: approvals}
	if rt != nil {
		opts.Launcher = rt
		rt.Start(ctx)
		defer rt.Close()
	}
	a, err := app.Start(ctx, cfg, opts)
	if err != nil {
		return err
	}
	defer a.Close()
	approvals.Start(ctx, a.Evidence, a.Admin, a.Gateway)
	if rt != nil {
		rt.SetEvidence(a.Evidence)
	}
	(&sandbox.API{Launcher: rt, Actor: adminapi.Actor}).Register(a.Admin)
	if _, err := consoleapi.Attach(a, log); err != nil { // E-24 console and its routes
		return fmt.Errorf("console: %w", err)
	}
	if err := a.Listen(); err != nil {
		return err
	}
	revision := "none (fail-closed)"
	if snap := a.Decider.Snapshot(); snap != nil {
		revision = snap.Revision
	}
	log.Info("smcpd listening", "mcp", cfg.ResourceURI(), "admin", cfg.AdminURL(), "policy_revision", revision,
		"profile", a.Profile.Profile, "release_label", a.Profile.Label)
	err = a.Serve(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
