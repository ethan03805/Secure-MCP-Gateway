package connector

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// ReasonDrift is the reason a hosted package revision is suspended for a
// difference reconciliation found (FR-22.33).
const ReasonDrift = "CONTEXTFORGE_DRIFT"

// ClassDrift is the event class of one reconciliation finding.
const ClassDrift = "contextforge_drift"

// ReconcileInterval is the polling period of FR-22.33.
const ReconcileInterval = 5 * time.Minute

// hostedPkg is one enabled hosted package registered in the running
// instance.
type hostedPkg struct {
	ServerID, Revision string
	Prov               *bundle.Provisioned
	ToBackend          map[string]string
	Expected           bundle.Expected
}

// ResolveHosted is the library's resolver of an enabled hosted package
// (manifest_version 2): it makes sure the bundled instance runs, registers
// the package with its own team, user, gateway, virtual server and token
// (FR-22.29, FR-22.34), checks that the virtual server serves exactly the
// manifest's backend names, runs the scope self-check over every
// registered hosted package, and returns the server entry that reaches the
// package's virtual server over loopback (FR-22.36). The token stays in
// the Connector; WrapLauncher hands it to the southbound transport.
func (c *Connector) ResolveHosted(sc config.Server, m *packaging.Manifest, rev library.Revision) (config.Server, error) {
	if !c.o.Config.ContextForge.Bundled {
		return sc, packaging.Errf(contextforge.ReasonContextForgeDisabled, "%s is a hosted package and [contextforge] bundled is false", rev.Key())
	}
	if c.instErr != nil {
		return sc, c.instErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := c.waitHealthy(ctx, "E-36"); err != nil {
		return sc, err
	}
	a := c.admin()
	c.hostedMu.Lock()
	defer c.hostedMu.Unlock()
	if started := c.inst.Status().StartedAt; !started.Equal(c.cleanedAt) {
		// A new instance start: remove what an earlier run left behind
		// and register every package again (D-16 is not an authority).
		if _, err := a.Reconcile(ctx, nil); err != nil {
			return sc, err
		}
		c.hosted, c.cleanedAt = map[string]*hostedPkg{}, started
	}
	slug := m.Upstream.GatewaySlug
	user := "user-" + slug
	if _, err := c.o.Broker.EnsureComponent(component, user, func() ([]byte, error) {
		v, err := bundle.NewCredential()
		return []byte(v), err
	}); err != nil {
		return sc, err
	}
	vals, err := c.o.Broker.DeliverComponent(component, []string{user})
	if err != nil {
		return sc, err
	}
	pw := string(vals[user])
	clear(vals[user])
	target, err := c.endpointFor(m.Upstream.URL)
	if err != nil {
		return sc, err
	}
	prov, err := a.Provision(ctx, bundle.PackageSpec{Slug: slug, URL: target, Transport: m.Upstream.Transport}, pw)
	if err != nil {
		if prov != nil {
			_ = a.Deprovision(context.WithoutCancel(ctx), prov)
		}
		return sc, packaging.Wrap(packaging.ReasonProbeFailed, "registering "+rev.Key()+" in the bundled instance", err)
	}
	hp := &hostedPkg{ServerID: rev.ServerID, Revision: rev.Revision, Prov: prov, ToBackend: map[string]string{},
		Expected: bundle.Expected{Provisioned: *prov, URL: target, Tools: map[string]string{}}}
	var want []string
	for _, t := range m.Tools {
		hp.ToBackend[t.Name] = t.BackendName
		hp.Expected.Tools[t.BackendName] = t.Description
		want = append(want, t.BackendName)
	}
	sort.Strings(want)
	if got := slices.Clone(prov.Tools); !slices.Equal(got, want) {
		_ = a.Deprovision(context.WithoutCancel(ctx), prov)
		return sc, packaging.Errf(ReasonDrift, "%s: the bundled instance serves %v, the manifest names %v", rev.Key(), got, want)
	}
	c.hosted[prov.ServerID] = hp
	pkgs := make([]*bundle.Provisioned, 0, len(c.hosted))
	for _, x := range c.hosted {
		pkgs = append(pkgs, x.Prov)
	}
	if f := a.SelfCheck(ctx, pkgs); len(f) > 0 {
		err := packaging.Errf(bundle.ReasonScopeBroken, "the scope self-check found %d findings, for example %s: %s", len(f), f[0].Probe, f[0].Detail)
		c.scopeBroken(err)
		return sc, err
	}
	out := sc
	out.URL = c.inst.BaseURL() + "/servers/" + prov.ServerID + "/mcp"
	out.Command, out.Args, out.Env, out.Dir, out.Runtime, out.ArtifactRoot = "", nil, nil, "", "", ""
	return out, nil
}

// scopeBroken stops using the bundled instance: every hosted package is
// suspended with CONTEXTFORGE_SCOPE_BROKEN and the instance stopped
// (FR-22.29). The caller holds hostedMu.
func (c *Connector) scopeBroken(cause error) {
	for _, hp := range c.hosted {
		if c.o.Suspend != nil {
			_ = c.o.Suspend(hp.ServerID, hp.Revision, cause)
		}
	}
	c.hosted = map[string]*hostedPkg{}
	if c.o.Recorder != nil {
		_ = c.o.Recorder.Commit(c.instanceEvent("scope_broken", bundle.ReasonScopeBroken, map[string]any{"error": cause.Error()}))
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.StopInstance(ctx, "E-36")
	}()
}

// hostedFor returns the registered package a URL addresses.
func (c *Connector) hostedFor(url string) *hostedPkg {
	if c.inst == nil {
		return nil
	}
	base := c.inst.BaseURL()
	rest, ok := strings.CutPrefix(url, base+"/servers/")
	if base == "" || !ok {
		return nil
	}
	id, _, _ := strings.Cut(rest, "/")
	c.hostedMu.Lock()
	defer c.hostedMu.Unlock()
	return c.hosted[id]
}

// hostedLauncher gives a hosted package's connection its token and the
// backend-name wrapper.
type hostedLauncher struct {
	pipeline.Launcher
	get func() *Connector
}

// WrapLauncher returns inner with the hosted packages' connections taken
// care of: the package token as SMCP_UPSTREAM_TOKEN of the southbound
// transport (never in a configuration or file) and renameProcess around
// the connection. Put it outside southbound.Wrap and inside the Secret
// Broker's wrapper. get returns the Connector, which may be created after
// the launcher chain (nil: no hosted package).
func WrapLauncher(inner pipeline.Launcher, get func() *Connector) pipeline.Launcher {
	h := &hostedLauncher{Launcher: inner, get: get}
	if ea, ok := inner.(pipeline.EgressAware); ok {
		return &hostedEgressAware{hostedLauncher: h, ea: ea}
	}
	return h
}

type hostedEgressAware struct {
	*hostedLauncher
	ea pipeline.EgressAware
}

func (h *hostedEgressAware) SetEgress(a pipeline.EgressAttacher) { h.ea.SetEgress(a) }

// Launch implements pipeline.Launcher.
func (h *hostedLauncher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	c := h.get()
	var hp *hostedPkg
	if c != nil {
		hp = c.hostedFor(spec.URL)
	}
	if hp == nil {
		return h.Launcher.Launch(ctx, spec)
	}
	env := maps.Clone(spec.Env)
	if env == nil {
		env = map[string]string{}
	}
	env[southbound.TokenEnv] = hp.Prov.Token
	spec.Env = env
	proc, err := h.Launcher.Launch(ctx, spec)
	if err != nil {
		return nil, err
	}
	return renameProcess(proc, hp.ToBackend, func(string) { c.ReconcileNow() }), nil
}

// ReconcileNow asks the reconciliation loop for an immediate pass (an
// "Unknown tool" answer, FR-22.33).
func (c *Connector) ReconcileNow() {
	select {
	case c.reconcileReq <- struct{}{}:
	default:
	}
}

// reconcile runs one pass over the registered hosted packages: removed
// objects and drift are journaled as contextforge_drift events, and every
// package with drift is suspended (FR-22.33, SR-3.8-2).
func (c *Connector) reconcile(ctx context.Context) {
	if c.inst == nil || !c.inst.Healthy() {
		return
	}
	c.hostedMu.Lock()
	defer c.hostedMu.Unlock()
	if len(c.hosted) == 0 {
		return
	}
	exp := make([]bundle.Expected, 0, len(c.hosted))
	for _, hp := range c.hosted {
		exp = append(exp, hp.Expected)
	}
	drift, err := c.admin().Reconcile(ctx, exp)
	if err != nil {
		c.o.Log.Warn("contextforge reconciliation", "error", err)
		return
	}
	bySlug := map[string]*hostedPkg{}
	for id, hp := range c.hosted {
		bySlug[hp.Prov.Slug] = c.hosted[id]
	}
	suspended := map[string]bool{}
	for _, d := range drift {
		if c.o.Recorder != nil {
			ev := c.instanceEvent("drift", ReasonDrift, map[string]any{"package": d.Package, "kind": d.Kind, "object": d.Object,
				"detail": d.Detail, "removed": d.Removed})
			ev.Class = ClassDrift
			_ = c.o.Recorder.Commit(ev)
		}
		hp := bySlug[d.Package]
		if hp == nil || suspended[hp.Prov.ServerID] {
			continue
		}
		suspended[hp.Prov.ServerID] = true
		if c.o.Suspend != nil {
			_ = c.o.Suspend(hp.ServerID, hp.Revision, packaging.Errf(ReasonDrift, "%s: %s", d.Kind, d.Detail))
		}
		delete(c.hosted, hp.Prov.ServerID)
	}
}
