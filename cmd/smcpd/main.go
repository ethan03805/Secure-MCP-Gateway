// Command smcpd is the Secure MCP Gateway daemon: the harness listener with
// OAuth 2.1 sessions, policy decisions, dispatch to stdio MCP servers, the
// signed evidence journal and the loopback control API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleauth"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/filterapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/obspolicy"
	"github.com/ethan03805/secure-mcp-gateway/internal/openapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/ops"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/principals"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/remote"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
	"github.com/ethan03805/secure-mcp-gateway/internal/versions"
)

func main() {
	cfgPath := flag.String("config", "smcp.toml", "configuration file (TOML)")
	logLevel := flag.String("log-level", "", "diagnostic log level (debug, info, warn, error); overrides [log] level")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(versionLine())
		return
	}
	if err := platformRun(*cfgPath, *logLevel); err != nil {
		fmt.Fprintln(os.Stderr, "smcpd:", err)
		os.Exit(1)
	}
}

// journalRetry is how often smcpd checks, while fail-closed, whether the
// journal directory has become writable (FR-9.17).
var journalRetry = 2 * time.Second

// journalWritable reports whether a file can be created in the journal
// directory, the condition for retrying the start.
func journalWritable(cfg *config.Config) func() bool {
	dir := filepath.Join(cfg.State.Dir, "journal")
	return func() bool {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false
		}
		f, err := os.CreateTemp(dir, ".writable-*")
		if err != nil {
			return false
		}
		name := f.Name()
		f.Close()
		return os.Remove(name) == nil
	}
}

// attachSecrets opens the vault and builds the Secret Broker (E-19, E-20)
// when [secrets] is configured, and returns nil otherwise. It registers the
// vault health check (FR-7.11) and the broker's leak fingerprints with the
// Observation Collector (FR-6.10); app.Start registers the same
// fingerprints with the Response Inspection Pipeline (E-11).
func attachSecrets(cfg *config.Config, opts *app.Options, obs *analytics.Service, mon *health.Monitor, log *slog.Logger) (*secrets.Service, error) {
	sec, err := secrets.Configure(cfg, opts, nil, log)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	if sec == nil {
		return nil, nil
	}
	mon.Register("vault", health.Vault(sec.Vault.Check)) // FR-7.11: critical while the vault cannot be read
	fps := sec.Broker.Fingerprints()
	obs.SetSecretScanner(func(b []byte) int { return len(fps.Scan(b)) })
	return sec, nil
}

// versionLine is what smcpd --version prints: the release version set by
// the build (GoReleaser -X .../internal/backend.Version).
func versionLine() string { return "smcpd " + backend.Version }

// notifyMode names the approval notifier for the elements report.
func notifyMode(m string) string {
	if m == "" {
		return "auto"
	}
	return m
}

// installMode is the SR-4-2 installation mode that this process knows
// better than profile.DetectHost: the Windows machine-mode service sets
// windows-machine before run (main_windows.go). Empty means detect.
var installMode string

// machineRuntime makes a Windows machine-mode Gateway contain its packaged
// servers (FR-21.13, FR-21.14): with installation mode windows-machine,
// [runtime] sandbox "none" (the Standalone default, which an older
// smcpctl install --machine left in place) becomes "appcontainer", so the
// package library keeps each enabled revision's AppContainer placement
// (internal/winsandbox.Placements under <state>/appcontainer) and every
// packaged server starts in it under NT SERVICE\smcpd. It reports whether
// it changed the configuration. Any other mode or sandbox is left alone.
func machineRuntime(cfg *config.Config, mode string) bool {
	if mode != profile.ModeWindowsMachine || cfg.Runtime.Sandbox != "none" {
		return false
	}
	cfg.Runtime.Sandbox = "appcontainer"
	return true
}

// hostOverride returns the host for app.Options: nil (detect) unless
// mode is set, and then the detected host with that installation mode.
func hostOverride(mode string) *profile.Host {
	if mode == "" {
		return nil
	}
	h := profile.DetectHost()
	h.InstallMode = mode
	return &h
}

// run starts the Gateway and serves until parent is cancelled, SIGINT or
// SIGTERM arrives, or a listener fails. platformRun calls it: with
// context.Background() on Linux and macOS, and on Windows with the context
// of the service or of the per-user stop event (main_windows.go).
func run(parent context.Context, cfgPath, level string) error {
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
	if machineRuntime(cfg, installMode) {
		log.Warn(`Windows machine mode: [runtime] sandbox is "none"; packaged servers run in their AppContainer placements (sandbox = "appcontainer", FR-21.13)`)
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	prep, err := ops.Prepare(cfg) // E-22: finish interrupted rotations
	if err != nil {
		return err
	}
	// The configured listeners are bound before anything opens a port-0
	// socket (the egress proxy of each server instance), which could
	// otherwise be given one of the configured ports.
	lns, err := app.BindListeners(cfg)
	if err != nil {
		return err
	}
	defer lns.Close()
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
	// G-03, G-04, G-06, G-08: published observation objects overlay the
	// [observation] table of the copy the analytics service reads, and the
	// G-08 memory budget the [graph] budget of the copy the mirror reads.
	objs, err := obspolicy.Open(cfg)
	if err != nil {
		return fmt.Errorf("observation objects: %w", err)
	}
	obsCfg := *cfg
	if err := objs.Apply(&obsCfg); err != nil {
		log.Error("published observation objects not applied; smcp.toml settings kept for them", "err", err)
	}
	mirror, err := graph.New(graph.Options{Config: &obsCfg, Log: log}) // E-25, E-26, E-28: never gates enforcement
	if err != nil {
		return fmt.Errorf("graph: %w", err)
	}
	mon.Register("graph", mirror.HealthCheck())                                                // degraded, never fail-closed, while Neo4j is unreachable
	mon.Register("revocation_feed", health.Every(time.Minute, func(time.Time) []health.Cause { // SR-3-4
		if stale, why := pkgs.FeedStale(); stale {
			return []health.Cause{{Name: "revocation_feed_stale", Detail: why}}
		}
		return nil
	}))
	opts := app.Options{Log: log, Approver: approvals, Approvals: approvals, HealthGate: mon.Gate, Packages: pkgs, Listeners: lns,
		Observers: map[string]audit.Observer{"graph": mirror}, Host: hostOverride(installMode)}
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
	opts.Spans = obs.SpanSink()                                                                          // FR-10.2 stage spans to the Observation Collector
	opts.SessionContext = func() (string, []string) { return obs.S.PolicyID, obs.S.Baseline.Dimensions } // FR-2.13
	opts.ObservationContext = func() (string, string, string) {                                          // FR-3.12 obligations
		return objs.InForce(obspolicy.KindAuditProfile), obs.S.PolicyID, objs.InForce(obspolicy.KindAnomalyResponse)
	}
	if o := obs.Observer(); o != nil {
		opts.Observers["observation"] = o
	}
	if rt != nil {
		opts.Launcher = rt
		rt.Start(ctx)
		defer rt.Close()
	}
	// url servers connect over Streamable HTTP (FR-5.28); innermost, so the
	// Secret Broker's teardown and the package checks wrap them too.
	opts.Launcher = southbound.Wrap(opts.Launcher)
	// E-36: hosted packages' connections get their package token and the
	// backend-name wrapper, inside the Secret Broker's wrapper.
	var cf *connector.Connector
	opts.Launcher = connector.WrapLauncher(opts.Launcher, func() *connector.Connector { return cf })
	sec, err := attachSecrets(cfg, &opts, obs, mon, log) // E-19, E-20; nil when [secrets] is absent
	if err != nil {
		return err
	}
	defer sec.Close()
	if cf, err = openContextForge(cfg, pkgs, sec, rt != nil, log); err != nil { // E-36 (planned v1.3.0)
		return err
	}
	defer cf.Close()
	if cfg.ContextForge.Bundled {
		// FR-22.15: hosted packages' S1 grants go to their egress endpoints.
		opts.WrapInjector = func(next pipeline.SecretHeaderInjector) pipeline.SecretHeaderInjector { return cf.S1Router(next) }
	}
	a, err := app.Start(ctx, cfg, opts)
	// FR-9.17: while the Evidence Journal cannot be opened for writing,
	// harness requests get -31004; Start is retried once the journal
	// directory is writable again.
	for errors.Is(err, app.ErrJournal) {
		log.Error("evidence journal cannot be opened; answering harness requests with -31004 until it is writable", "err", err)
		if serr := edge.ServeFailClosed(ctx, cfg, lns.Harness, edge.ReasonJournalUnavailable, journalWritable(cfg), journalRetry); serr != nil {
			return fmt.Errorf("%w (while fail-closed: %w)", err, serr)
		}
		log.Info("evidence journal directory is writable; starting")
		a, err = app.Start(ctx, cfg, opts)
	}
	if err != nil {
		return err
	}
	defer a.Close()
	watchConsoleClose(a, log) // FR-21.7: no-op off Windows
	if obs.Scorer != nil {
		a.Decider.SetBaseline(obs.Scorer.SnapshotID) // FR-3.11
	}
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
	// Objects published while smcpd runs apply to the running observation
	// components at once (obs.Update); the rest wait for the next start.
	objs.SetApplier(obs.Update)
	(&obspolicy.Service{Store: objs, Evidence: a.Evidence}).Register(a.Admin)
	(&principals.Service{Dir: pdir, Sessions: a.Store, Snapshot: a.Decider.Snapshot, Evidence: a.Evidence, Log: log, Gate: a.Gateway.Serialize}).Register(a.Admin)
	mirror.Register(a.Admin)
	// E-28: purge of versions no unexpired audit record references (SR-6.14-1).
	vs := &versions.Service{JournalDir: a.Journal.Dir(), Evidence: a.Evidence}
	if obs.Baselines != nil {
		vs.SetPurger(versions.KindBaselineSnapshot, versions.BaselinePurger(obs.Baselines.Store()))
	}
	vs.Register(a.Admin)
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
	attachContextForge(ctx, cf, a, mon)
	// Every component exists from here on: the elements report reads them.
	w := &wiring{app: a, approvals: approvals, notify: notifyMode(cfg.Approvals.Notify), packages: pkgs, sandbox: rt, secrets: sec,
		mirror: mirror, obs: obs, remote: rs, console: true, contextforge: cf}
	// E-21/E-22/E-23: health monitor, metrics, export, keys, backup, reload.
	opsrt, err := ops.Attach(ctx, a, ops.Options{ConfigPath: cfgPath, Log: log, LogLevel: lv, Monitor: mon, MetricsListener: lns.Metrics,
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
		"profile", a.Profile.Profile, "release_label", a.Profile.Label, "installation_mode", a.Profile.InstallMode, "diagnostic_log", cfg.Log.File)
	err = a.Serve(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
