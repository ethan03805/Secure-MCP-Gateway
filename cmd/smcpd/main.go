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
	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleauth"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/filterapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/obspolicy"
	"github.com/ethan03805/secure-mcp-gateway/internal/openapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/ops"
	"github.com/ethan03805/secure-mcp-gateway/internal/principals"
	"github.com/ethan03805/secure-mcp-gateway/internal/remote"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
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

// notifyMode names the approval notifier for the elements report.
func notifyMode(m string) string {
	if m == "" {
		return "auto"
	}
	return m
}

func run(cfgPath, level string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if level == "" {
		level = cfg.Log.Level
	}
	log, lv, logFile, err := diag.NewDaemon(diag.Options{Level: level, Format: cfg.Log.Format, Stderr: os.Stderr,
		File: cfg.Log.File, MaxBytes: cfg.Log.MaxBytes, MaxFiles: cfg.Log.MaxFiles})
	if err != nil {
		return err
	}
	defer logFile.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	prep, err := ops.Prepare(cfg) // E-22: finish interrupted rotations
	if err != nil {
		return err
	}
	if prep.EvidenceRotation != "" {
		log.Warn("interrupted evidence-key rotation resolved", "action", prep.EvidenceRotation)
	}
	mon := health.New(health.Options{Log: log}) // E-23
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
	pkgs, err := library.OpenRuntime(cfg, log) // E-13, E-14
	if err != nil {
		return fmt.Errorf("packages: %w", err)
	}
	mirror, err := graph.New(graph.Options{Config: cfg, Log: log}) // E-25, E-26, E-28: never gates enforcement
	if err != nil {
		return fmt.Errorf("graph: %w", err)
	}
	mon.Register("graph", mirror.HealthCheck()) // degraded, never fail-closed, while Neo4j is unreachable
	opts := app.Options{Log: log, Approver: approvals, Approvals: approvals, HealthGate: mon.Gate, Packages: pkgs,
		Observers: map[string]audit.Observer{"graph": mirror}}
	// G-03, G-04, G-06, G-08: published observation objects overlay the
	// [observation] table of the copy the analytics service reads.
	objs, err := obspolicy.Open(cfg)
	if err != nil {
		return fmt.Errorf("observation objects: %w", err)
	}
	obsCfg := *cfg
	if err := objs.Apply(&obsCfg); err != nil {
		log.Error("published observation objects not applied; smcp.toml settings kept for them", "err", err)
	}
	frameworkOf := func(id string) string { // FR-8.9: principals of the file and of the G-11 directory
		if p := cfg.FindPrincipal(id); p != nil {
			return p.Framework
		}
		return ""
	}
	obs, err := analytics.New(analytics.Options{Config: &obsCfg, Log: log, FrameworkOf: frameworkOf}) // SS-10, E-27
	if err != nil {
		return fmt.Errorf("observation: %w", err)
	}
	mon.Register("observation", obs.HealthCheck()) // degraded while the Observation Store cannot be opened, or while observation is degraded (FR-9.12)
	mon.AddQuota(obs.StorageQuota())               // FR-9.15
	opts.ExtraFilters = obs.RegisterFilters
	if o := obs.Observer(); o != nil {
		opts.Observers["observation"] = o
	}
	if rt != nil {
		opts.Launcher = rt
		rt.Start(ctx)
		defer rt.Close()
	}
	sec, err := secrets.Configure(cfg, &opts, nil, log) // E-19, E-20; nil when [secrets] is absent
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	defer sec.Close()
	a, err := app.Start(ctx, cfg, opts)
	if err != nil {
		return err
	}
	defer a.Close()
	approvals.Start(ctx, a.Evidence, a.Admin, a.Gateway)
	obs.Start(ctx, a.Evidence, a.Admin, func() uint64 { return a.Evidence.Dropped()["observation"] })
	obs.SetMetricSources(analytics.MetricSources{SigningLag: a.Journal.Unsigned, // P-247, P-244 (FR-10.9)
		GraphMemory: func() any {
			if st := mirror.Status(context.Background(), false); st.Enabled {
				return st.Memory
			}
			return nil
		}})
	defer obs.Close()
	if rt != nil {
		rt.SetEvidence(a.Evidence)
	}
	(&sandbox.API{Launcher: rt, Actor: adminapi.Actor}).Register(a.Admin)
	if _, err := consoleapi.Attach(a, log); err != nil { // E-24 console and its routes
		return fmt.Errorf("console: %w", err)
	}
	// G-11: principals and credentials managed from the console, seen by
	// every element through config.FindPrincipal and FindClient.
	pdir, err := principals.Open(cfg)
	if err != nil {
		return fmt.Errorf("principal directory: %w", err)
	}
	cfg.SetDirectory(pdir)
	(&obspolicy.Service{Store: objs, Evidence: a.Evidence}).Register(a.Admin)
	(&principals.Service{Dir: pdir, Sessions: a.Store, Snapshot: a.Decider.Snapshot, Evidence: a.Evidence, Log: log}).Register(a.Admin)
	mirror.Register(a.Admin)
	mirror.Start(ctx, a.Evidence)
	defer mirror.Close()
	sec.Attach(a.Admin, a.Registry)
	go sec.Run(ctx, 0)
	rs, err := remote.New(remote.Options{Config: cfg, Store: a.Store, Evidence: a.Evidence, Gateway: a.Gateway, Log: log}) // FR-16
	if err != nil {
		return fmt.Errorf("remote access: %w", err)
	}
	defer rs.Close()
	rs.Register(a.Admin)
	// Every component exists from here on: the elements report reads them.
	w := &wiring{app: a, approvals: approvals, notify: notifyMode(cfg.Approvals.Notify), packages: pkgs, sandbox: rt, secrets: sec,
		mirror: mirror, obs: obs, remote: rs, console: true}
	// E-21/E-22/E-23: health monitor, metrics, export, keys, backup, reload.
	opsrt, err := ops.Attach(ctx, a, ops.Options{ConfigPath: cfgPath, Log: log, LogLevel: lv, Monitor: mon,
		PendingApprovals: func() int { return len(approvals.List(approval.StatePending)) },
		Elements:         func() any { return w.elements() }})
	if err != nil {
		return err
	}
	defer opsrt.Close()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			if _, err := opsrt.Reload("signal:SIGHUP"); err != nil {
				log.Error("SIGHUP reload failed; running configuration kept", "err", err)
			}
		}
	}()
	// E-24: console accounts of the remaining Appendix C roles, the G-02
	// filter test workbench and the OpenAPI document of every route.
	consoleauth.New(consoleauth.Options{Config: cfg, Evidence: a.Evidence, Log: log}).Register(a.Admin)
	filterapi.RegisterRoutes(a.Admin, cfg)
	openapi.Register(a.Admin)
	if err := a.Listen(); err != nil {
		return err
	}
	if err := rs.Start(ctx); err != nil {
		return err
	}
	revision := "none (fail-closed)"
	if snap := a.Decider.Snapshot(); snap != nil {
		revision = snap.Revision
	}
	for _, e := range w.elements() {
		log.Info("element", "id", e.ID, "name", e.Name, "state", e.State, "detail", e.Detail)
	}
	log.Info("smcpd listening", "mcp", cfg.ResourceURI(), "admin", cfg.AdminURL(), "policy_revision", revision,
		"profile", a.Profile.Profile, "release_label", a.Profile.Label, "diagnostic_log", cfg.Log.File)
	err = a.Serve(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
