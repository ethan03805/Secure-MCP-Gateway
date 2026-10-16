// Package app wires the Gateway's elements together from a validated
// configuration: the evidence journal and its observers, the policy
// decider, the session store and OAuth server, the backend registry, the
// enforcement edge and the control API. cmd/smcpd and the end-to-end tests
// both start the Gateway through it, so the wiring exists once.
//
// Elements built later plug in through Options (the seams of
// internal/pipeline, the approval queue of the control API and evidence
// observers) rather than by editing this file.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Options are the seams. Zero values select the defaults.
type Options struct {
	Log       *slog.Logger
	Launcher  pipeline.Launcher       // default SubprocessLauncher (standalone)
	Manifests pipeline.ManifestSource // default LiveManifest (unverified)
	Secrets   pipeline.SecretBroker   // default NoSecrets
	Approver  pipeline.Approver       // default RefuseApprover
	Filters   *pipeline.Filters       // default NewFilters (schema-validate)
	Approvals adminapi.Approvals      // default none
	// Observers receive evidence after the journal accepts it (E-26, E-29).
	Observers map[string]audit.Observer
	// Host overrides host detection (tests).
	Host *profile.Host
	// GuardConfig bounds sign-in endpoints.
	GuardConfig authguard.Config
	// JanitorInterval is how often expired state is pruned (default 30s).
	JanitorInterval time.Duration
	// ConsoleURL is the base of approval deep links (default the admin URL).
	ConsoleURL string
}

// App is a started Gateway.
type App struct {
	Config       *config.Config
	Journal      *audit.Journal
	Evidence     *audit.Fanout
	Decider      *policy.Decider
	Store        *session.Store
	OAuth        *session.OAuth
	Registry     *backend.Registry
	Gateway      *edge.Gateway
	Admin        *adminapi.Server
	Profile      profile.Report
	Capabilities *pipeline.Capabilities
	TLS          keys.TLSStatus

	log       *slog.Logger
	janitor   time.Duration
	harnessLn net.Listener
	adminLn   net.Listener
	closeOnce sync.Once
}

func listenerNames(cfg *config.Config) []string {
	var names []string
	for _, a := range []string{cfg.Listener.Address, cfg.AdminListener.Address} {
		if h, _, err := net.SplitHostPort(a); err == nil {
			names = append(names, h)
		}
	}
	if u, err := url.Parse(cfg.Listener.PublicURL); err == nil {
		names = append(names, u.Hostname())
	}
	return names
}

// Start builds every component. On error everything started so far is
// closed.
func Start(ctx context.Context, cfg *config.Config, o Options) (a *App, err error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.JanitorInterval <= 0 {
		o.JanitorInterval = 30 * time.Second
	}
	a = &App{Config: cfg, log: o.Log, janitor: o.JanitorInterval}
	defer func() {
		if err != nil {
			a.Close()
			a = nil
		}
	}()
	evKey, err := keys.LoadEvidenceKey(cfg.State.Dir)
	if err != nil {
		return a, fmt.Errorf("evidence key (run `smcpctl bootstrap` first): %w", err)
	}
	if a.TLS, err = keys.RotateIfDue(cfg.State.Dir, time.Now(), listenerNames(cfg)...); err != nil {
		return a, fmt.Errorf("tls certificates: %w", err)
	}
	if a.TLS.LeafRotated {
		o.Log.Warn("listener certificate reissued", "not_after", a.TLS.LeafNotAfter)
	}
	snap, err := policy.Load(cfg.Policy.File)
	if err != nil {
		return a, fmt.Errorf("policy: %w", err)
	}
	if a.Journal, err = audit.Open(filepath.Join(cfg.State.Dir, "journal"), evKey, audit.Options{}); err != nil {
		return a, fmt.Errorf("journal: %w", err)
	}
	for _, r := range a.Journal.Recovered() {
		o.Log.Warn("journal segment recovered after a crash", "segment", r.Segment, "events", r.Events, "truncated_bytes", r.TruncatedBytes)
	}
	a.Evidence = audit.NewFanout(a.Journal, o.Log)
	for name, obs := range o.Observers {
		a.Evidence.AddObserver(name, obs, 0)
	}

	if o.Launcher == nil {
		o.Launcher = pipeline.SubprocessLauncher{}
	}
	host := profile.DetectHost()
	if o.Host != nil {
		host = *o.Host
	}
	if a.Profile, err = profile.Resolve(cfg.Profile.Mode, o.Launcher.Name(), o.Launcher.Confined(), host); err != nil {
		return a, err
	}
	if a.Profile.Profile == profile.Standalone {
		o.Log.Warn("standalone profile: server instances run unconfined; high-risk server classes are refused", "reasons", a.Profile.Reasons)
	}

	a.Capabilities = pipeline.NewCapabilities(2 * cfg.Limits.ClientDeadline.Duration)
	if a.Registry, err = backend.Start(ctx, cfg.Servers, backend.Options{
		Limits: backend.Limits{PerPrincipal: cfg.Limits.ToolConcurrencyPerUser, Total: cfg.Limits.ToolConcurrencyTotal, Queue: cfg.Limits.ToolQueue,
			UpstreamTimeout: cfg.Limits.UpstreamTimeout.Duration, ResultBytes: cfg.Limits.ResultBytes},
		Launcher: o.Launcher, Manifests: o.Manifests, Secrets: o.Secrets, Capabilities: a.Capabilities, Log: o.Log,
	}); err != nil {
		return a, fmt.Errorf("backend servers: %w", err)
	}
	for alias, s := range a.Registry.Servers() {
		o.Log.Info("server enabled", "alias", alias, "revision", s.Revision, "era", s.Era, "tools", len(s.Tools), "verified", s.Verified)
	}

	a.Decider = policy.NewDecider(snap, cfg.Limits.PrincipalCallsPerMin)
	a.Store = session.NewStore(cfg, a.Decider.Snapshot)
	guard := authguard.New(o.GuardConfig)
	a.OAuth = session.NewOAuth(cfg, a.Store, a.Evidence, guard)
	if o.ConsoleURL == "" {
		o.ConsoleURL = cfg.AdminURL()
	}
	if a.Gateway, err = edge.New(edge.Deps{Config: cfg, Store: a.Store, OAuth: a.OAuth, Decider: a.Decider, Registry: a.Registry,
		Evidence: a.Evidence, EvidenceErr: a.Journal.Err, Log: o.Log, Profile: a.Profile, Approver: o.Approver, Filters: o.Filters,
		Capabilities: a.Capabilities, ConsoleURL: o.ConsoleURL}); err != nil {
		return a, err
	}
	if a.Admin, err = adminapi.New(adminapi.Options{Config: cfg, Controller: a.Gateway, Evidence: a.Evidence, Guard: guard, Approvals: o.Approvals, Log: o.Log}); err != nil {
		return a, err
	}
	if err = a.Evidence.Commit(audit.Event{Class: "gateway", Origin: "E-23", Outcome: "started", PolicyRevision: snap.Revision, PolicyStatus: "not_evaluated",
		Detail: map[string]any{"version": backend.Version, "listener": cfg.Listener.Address, "admin_listener": cfg.AdminListener.Address,
			"profile": a.Profile.Profile, "release_label": a.Profile.Label}}); err != nil {
		return a, fmt.Errorf("journal: %w", err)
	}
	return a, nil
}

// Listen binds both listeners. Connections queue in the backlog until Serve
// runs, so callers may connect as soon as Listen returns.
func (a *App) Listen() error {
	var err error
	if a.harnessLn, err = a.Gateway.Listen(); err != nil {
		return err
	}
	if a.adminLn, err = a.Admin.Listen(); err != nil {
		a.harnessLn.Close()
		return err
	}
	return nil
}

// Serve runs both listeners and the janitors until ctx ends or a listener
// fails. Listen must have been called.
func (a *App) Serve(ctx context.Context) error {
	if a.harnessLn == nil || a.adminLn == nil {
		return errors.New("app: Listen first")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.Gateway.RunJanitors(ctx, a.janitor)
	errc := make(chan error, 2)
	go func() { errc <- a.Gateway.Serve(ctx, a.harnessLn) }()
	go func() { errc <- a.Admin.Serve(ctx, a.adminLn) }()
	err := <-errc
	cancel()
	err2 := <-errc
	return errors.Join(err, err2)
}

// Close stops everything and seals the journal. It is safe to call more
// than once.
func (a *App) Close() {
	a.closeOnce.Do(func() {
		if a.Gateway != nil {
			a.Gateway.Close()
		}
		if a.Registry != nil {
			a.Registry.Close()
		}
		if a.Evidence != nil {
			if err := a.Evidence.Commit(audit.Event{Class: "gateway", Origin: "E-23", Outcome: "stopped", PolicyStatus: "not_evaluated"}); err != nil {
				a.log.Error("evidence write failed at shutdown", "err", err)
			}
			a.Evidence.Close()
		}
		if a.Journal != nil {
			if err := a.Journal.Close(); err != nil {
				a.log.Error("journal close failed", "err", err)
			}
		}
	})
}
