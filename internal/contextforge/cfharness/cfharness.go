// Package cfharness runs the ContextForge Connector (E-36) against the
// ContextForge stand-in (cftest.StandIn) and hosted MCP fixtures on HTTPS,
// with the hosted egress listener of a real Egress Broker between them,
// for tests that do not run the pinned image: the connector's external
// tests and the hostile ContextForge rows (SRS FR-22.43).
//
// Fixture hosts are names under example.com (the httptest certificate's
// names); the broker resolves them to public documentation-free addresses
// and its dialer connects those to the fixtures on loopback, recording
// every address it dialed. A name may instead resolve to a private or
// metadata address, which the broker must refuse.
package cfharness

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// Fixture is one hosted MCP server on HTTPS.
type Fixture struct {
	Host string
	// APIKey, when set, is required in X-Api-Key (401 otherwise).
	APIKey string
	srv    *httptest.Server
	ip     netip.Addr

	mu       sync.Mutex
	requests []http.Header
}

// Headers returns the request headers the fixture received.
func (f *Fixture) Headers() []http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// Env is a Connector with a stand-in instance and hosted fixtures.
type Env struct {
	t        *testing.T
	State    string
	StandIn  *cftest.StandIn
	SI       *httptest.Server
	Conn     *connector.Connector
	Lib      *library.Library
	Rec      *audit.Memory
	Fanout   *audit.Fanout
	Broker   *secrets.Broker
	Fixtures map[string]*Fixture
	Runner   *Runner
	// WrapManifests, when set, wraps the runtime's manifest source at
	// Launch (the Gateway's metadata scan, filters.Inspector.Manifests).
	WrapManifests func(pipeline.ManifestSource) pipeline.ManifestSource

	mu       sync.Mutex
	resolve  map[string][]netip.Addr
	dialed   []string
	fixtures map[netip.Addr]*Fixture
	next     byte
}

// Entry is one hosted catalog entry of the harness's catalog.
type Entry struct {
	ID, URL, AuthType string
	RequiresAPIKey    bool
}

// Options configure New.
type Options struct {
	Entries []Entry
	// Tools are the fixtures' tool names (default "echo" and "get_time").
	Tools []string
	// Descriptions replace the fixtures' tool descriptions by tool name.
	Descriptions map[string]string
	// Results replace the fixtures' answers by tool name: the function
	// gets the fixture's host.
	Results map[string]func(host string) *mcp.CallToolResult
	// StandIn, when set, is the stand-in with its knobs; New sets its
	// AdminToken.
	StandIn       *cftest.StandIn
	RenewBefore   time.Duration
	RenewInterval time.Duration
	// Resolve maps extra names to addresses (private, metadata).
	Resolve map[string]string
	// LockKeys and UpgradeHealthWait are the Connector's upgrade options
	// (FR-22.31).
	LockKeys          []minisign.PublicKey
	UpgradeHealthWait time.Duration
}

// New builds the environment: a vault and Secret Broker, a library, the
// stand-in, one fixture per https entry host and the Connector.
func New(t *testing.T, o Options) *Env {
	t.Helper()
	e := &Env{t: t, State: t.TempDir(), Rec: &audit.Memory{}, Fixtures: map[string]*Fixture{}, resolve: map[string][]netip.Addr{},
		fixtures: map[netip.Addr]*Fixture{}, next: 10}
	e.Fanout = audit.NewFanout(e.Rec, nil)
	tools := o.Tools
	if len(tools) == 0 {
		tools = []string{"echo", "get_time"}
	}
	var catalog strings.Builder
	catalog.WriteString("catalog_servers:\n")
	for _, en := range o.Entries {
		auth := en.AuthType
		if auth == "" {
			auth = "Open"
		}
		fmt.Fprintf(&catalog, "  - id: %s\n    name: %s\n    provider: Example\n    auth_type: %s\n    url: %q\n    description: Fixture %s.\n", en.ID, en.ID, auth, en.URL, en.ID)
		if en.RequiresAPIKey {
			catalog.WriteString("    requires_api_key: true\n")
		}
		host, _, err := hostOf(en.URL)
		if err != nil || !strings.HasSuffix(host, "example.com") || e.Fixtures[host] != nil {
			continue
		}
		f := e.addFixture(host, tools, o.Descriptions, o.Results)
		if en.RequiresAPIKey {
			f.APIKey = "fixture-api-key-" + en.ID
		}
	}
	for name, addr := range o.Resolve {
		e.resolve[name] = []netip.Addr{netip.MustParseAddr(addr)}
	}
	file := filepath.Join(t.TempDir(), "catalog.yml")
	if err := os.WriteFile(file, []byte(catalog.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf("[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[state]\ndir = %q\n[approvals]\nnotify = \"off\"\n[contextforge]\nbundled = true\ncatalog_file = %q\ncatalog_sha256 = %q\n",
		e.State, file, packaging.SHA256Hex([]byte(catalog.String())))))
	if err != nil {
		t.Fatal(err)
	}
	if e.Lib, err = library.Open(library.Options{StateDir: e.State, HostedAllowed: func() bool { return true }}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Lib.Close() })
	e.Lib.SetRecorder(e.Fanout)
	e.Broker = newBroker(t, e.Fanout)
	e.StandIn = o.StandIn
	if e.StandIn == nil {
		e.StandIn = &cftest.StandIn{}
	}
	e.StandIn.AdminToken = "standin-admin-token"
	e.SI = httptest.NewServer(e.StandIn)
	t.Cleanup(e.SI.Close)
	e.Runner = &Runner{base: e.SI.URL, admin: e.StandIn.AdminToken}
	pool := x509.NewCertPool()
	for _, f := range e.Fixtures {
		pool.AddCert(f.srv.Certificate())
		break
	}
	open := func(opts egress.Options, listen netip.AddrPort, guest netip.Addr) (*egress.Hosted, error) {
		opts.RootCAs = pool
		opts.Resolver = resolverFunc(e.lookup)
		opts.Dial = e.dial
		return egress.NewHostedGuest(opts, listen, guest)
	}
	e.Conn, err = connector.New(connector.Options{Config: cfg, Library: e.Lib, Recorder: e.Fanout, Broker: e.Broker, Version: "test",
		Runner: e.Runner, Verifier: verifier{}, Egress: open, RenewBefore: o.RenewBefore, RenewInterval: o.RenewInterval,
		LockKeys: o.LockKeys, UpgradeHealthWait: o.UpgradeHealthWait})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Conn.Close)
	e.Fanout.AddDecorator(e.Conn.Decorate)
	e.Broker.SetInjector(e.Conn.S1Router(nil))
	e.enroll()
	return e
}

func hostOf(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	return strings.ToLower(u.Hostname()), u.Port(), nil
}

// addFixture starts an HTTPS MCP fixture for host with the named tools;
// each tool answers "<host> <tool> <arguments>".
func (e *Env) addFixture(host string, tools []string, desc map[string]string, results map[string]func(string) *mcp.CallToolResult) *Fixture {
	f := &Fixture{Host: host}
	s := mcp.NewServer(&mcp.Implementation{Name: "fx-" + host, Version: "1.0.0"}, nil)
	for _, n := range tools {
		d := "Fixture " + n + " of " + host + "."
		if v, ok := desc[n]; ok {
			d = v
		}
		mcp.AddTool(s, &mcp.Tool{Name: n, Description: d}, func(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
			if r, ok := results[n]; ok {
				return r(host), nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s %s %v", host, n, in)}}}, nil, nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Header.Clone())
		f.mu.Unlock()
		if f.APIKey != "" && r.Header.Get("X-Api-Key") != f.APIKey {
			http.Error(w, "missing API key", http.StatusUnauthorized)
			return
		}
		r.Host = "127.0.0.1"
		h.ServeHTTP(w, r)
	}))
	e.t.Cleanup(f.srv.Close)
	ip := netip.AddrFrom4([4]byte{93, 184, 216, e.next})
	e.next++
	f.ip = ip
	e.resolve[host] = []netip.Addr{ip}
	e.fixtures[ip] = f
	e.Fixtures[host] = f
	return f
}

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func (e *Env) lookup(_ context.Context, _, host string) ([]netip.Addr, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a, ok := e.resolve[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

func (e *Env) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	e.mu.Lock()
	e.dialed = append(e.dialed, addr)
	ap, err := netip.ParseAddrPort(addr)
	var f *Fixture
	if err == nil {
		f = e.fixtures[ap.Addr()]
	}
	e.mu.Unlock()
	if f == nil {
		return nil, fmt.Errorf("harness: no fixture at %s", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, f.srv.Listener.Addr().String())
}

// Dialed returns the addresses the Egress Broker dialed.
func (e *Env) Dialed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.dialed)
}

func newBroker(t *testing.T, rec audit.Recorder) *secrets.Broker {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	ks := secrets.Passphrase{Path: filepath.Join(dir, secrets.MasterKeyFile), Passphrase: func() (string, error) { return "test passphrase 123", nil }, WorkFactor: 10}
	if _, err := secrets.Init(dir, ks); err != nil {
		t.Fatal(err)
	}
	v, err := secrets.Open(dir, ks, secrets.VaultOptions{Overlap: time.Hour, Evidence: rec})
	if err != nil {
		t.Fatal(err)
	}
	b, err := secrets.NewBroker(secrets.BrokerOptions{Vault: v, Use: &secrets.UseSet{}, RuntimeDir: filepath.Join(t.TempDir(), "run")})
	if err != nil {
		t.Fatal(err)
	}
	b.AttachEvidence(rec)
	return b
}

// AddSecret stores an operator secret in the vault.
func (e *Env) AddSecret(name, value string) {
	e.t.Helper()
	if _, err := e.Broker.Vault().Create("op", secrets.CreateParams{Name: name, Type: "api_key", Owner: "op", Value: []byte(value)}); err != nil {
		e.t.Fatal(err)
	}
}

// UseS1 installs a Secret Use Policy that binds secret to alias's slot in
// mode S1: header (from template) at destination.
func (e *Env) UseS1(alias, slot, secret, header, template, destination string) {
	e.t.Helper()
	doc := map[string]any{"revision": "use-1",
		"slots":    []map[string]any{{"server": alias, "name": slot, "modes": []string{"S1"}, "header": header, "header_template": template, "destination": destination}},
		"policies": []map[string]any{{"id": slot, "secret": secret, "server": alias, "slot": slot, "mode": "S1", "tools": []string{"*"}, "purpose": "hosted API key"}}}
	raw, _ := json.Marshal(doc)
	u, err := secrets.CompileUsePolicy(raw, []config.Server{{Alias: alias, Package: "x"}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.Broker.SetUsePolicy(u)
}

func (e *Env) enroll() {
	e.t.Helper()
	a, err := packaging.LoadAnchors(e.State)
	if err != nil {
		e.t.Fatal(err)
	}
	pub := e.Conn.PublicKey()
	if _, err := a.Add("contextforge-import", pub, []string{"moderate", "high"}, time.Now().Add(time.Hour), time.Now(), "admin"); err != nil {
		e.t.Fatal(err)
	}
	if err := a.Save(); err != nil {
		e.t.Fatal(err)
	}
}

// Probe proposes an entry and waits for the probe's end.
func (e *Env) Probe(id string, in connector.LocalImport) (connector.ProposalView, error) {
	e.t.Helper()
	p, err := e.Conn.ProposeLocal(id, in, "op")
	if err != nil {
		return p, err
	}
	deadline := time.Now().Add(time.Minute)
	for p.State == "building" {
		if time.Now().After(deadline) {
			e.t.Fatal("probe still running")
		}
		time.Sleep(20 * time.Millisecond)
		p, _ = e.Conn.Proposal(p.ID)
	}
	return p, nil
}

// Import probes, accepts and enables an entry; it returns the revision.
func (e *Env) Import(id string, in connector.LocalImport) library.Revision {
	e.t.Helper()
	p, err := e.Probe(id, in)
	if err != nil {
		e.t.Fatal(err)
	}
	if p.State != "ready" {
		e.t.Fatalf("probe of %s: %s %s", id, p.ReasonCode, p.Error)
	}
	got, err := e.Conn.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil {
		e.t.Fatal(err)
	}
	rev, err := e.Lib.Enable(got.ServerID, got.Revision, library.EnableOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	return rev
}

// Gateway launches the enabled revisions through the library runtime, the
// Connector's resolver and launcher wrapper and the southbound transport,
// and starts the Connector's loops.
type Gateway struct {
	Reg     *backend.Registry
	RT      *library.Runtime
	Servers []config.Server
	Caps    *pipeline.Capabilities
}

// Launch starts a registry over revs.
func (e *Env) Launch(revs ...library.Revision) (*Gateway, error) {
	e.t.Helper()
	rt := library.NewRuntime(e.Lib, library.RuntimeOptions{Hosted: e.Conn.ResolveHosted})
	e.Conn.SetSuspend(rt.SuspendRevision)
	var scs []config.Server
	for _, r := range revs {
		scs = append(scs, config.Server{Alias: r.Alias, Package: r.ServerID})
	}
	servers, launcher, err := rt.Prepare(e.Fanout, scs, connector.WrapLauncher(southbound.Wrap(nil), func() *connector.Connector { return e.Conn }), true)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(context.Background())
	e.t.Cleanup(stop)
	e.Conn.Start(ctx)
	caps := pipeline.NewCapabilities(time.Minute)
	var ms pipeline.ManifestSource = rt
	if e.WrapManifests != nil {
		ms = e.WrapManifests(rt)
	}
	reg, err := backend.Start(context.Background(), servers, backend.Options{
		Limits:   backend.Limits{PerPrincipal: 2, Total: 4, Queue: 4, UpstreamTimeout: 20 * time.Second, ResultBytes: 1 << 20},
		Launcher: launcher, Manifests: ms, Capabilities: caps,
		// SR-6.18-1, SR-6.18-2: server-asserted text journaled as smcpd
		// does (app.recordAssertion), through the Connector's decorator.
		Asserted: func(x backend.Assertion) { _ = e.Fanout.Record(x.Event()) }, AssertInterval: 50 * time.Millisecond})
	if err != nil {
		return nil, err
	}
	e.t.Cleanup(func() { reg.Close() })
	rt.Started(func(alias, reason string) bool { return reg.Suspend(alias, reason) })
	return &Gateway{Reg: reg, RT: rt, Servers: servers, Caps: caps}, nil
}

// Call calls a public tool name.
func (g *Gateway) Call(public string, args map[string]any) (*mcp.CallToolResult, error) {
	ref := g.Reg.Resolve(public)
	if ref == nil {
		return nil, fmt.Errorf("not presented: %s", public)
	}
	b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: public}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return g.Reg.Call(context.Background(), backend.Dispatch{Principal: "p", Ref: ref, Capability: g.Caps.Issue(b), Binding: b, Arguments: raw})
}

// Runner is the stand-in's Runner: healthy once started, unless it runs
// the release named in Unhealthy. It stands in for an upgradable instance
// (FR-22.31): Release is the release it runs and Data stands for D-16,
// which a start of another release than the data's "migrates".
type Runner struct {
	base, admin string
	mu          sync.Mutex
	running     bool
	started     time.Time
	SSRF        []string
	Allow       netip.AddrPort
	Release     string
	Unhealthy   string
	Data        string
	backup      *string
	Removed     []string
}

// SetRelease switches the release of the next start.
func (r *Runner) SetRelease(l *contextforge.LockedRelease) error {
	r.mu.Lock()
	r.Release = l.Version
	r.mu.Unlock()
	return nil
}

// BackupData keeps a copy of Data.
func (r *Runner) BackupData(context.Context) error {
	r.mu.Lock()
	d := r.Data
	r.backup = &d
	r.mu.Unlock()
	return nil
}

// RestoreData puts the copy back.
func (r *Runner) RestoreData(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.backup == nil {
		return errors.New("no backup")
	}
	r.Data = *r.backup
	return nil
}

// DropBackup forgets the copy.
func (r *Runner) DropBackup(context.Context) error {
	r.mu.Lock()
	r.backup = nil
	r.mu.Unlock()
	return nil
}

// RemoveImageRef records the artifact the Connector removed.
func (r *Runner) RemoveImageRef(_ context.Context, ref string) error {
	r.mu.Lock()
	r.Removed = append(r.Removed, ref)
	r.mu.Unlock()
	return nil
}

func (r *Runner) Start(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running, r.started = true, time.Now()
	if r.Release != "" && !strings.HasSuffix(r.Data, "@"+r.Release) {
		r.Data += " migrated@" + r.Release
	}
	return nil
}

func (r *Runner) Stop(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	return nil
}

func (r *Runner) Status() bundle.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return bundle.Status{State: bundle.StateStopped}
	}
	if r.Unhealthy != "" && r.Release == r.Unhealthy {
		return bundle.Status{State: bundle.StateStarting, StartedAt: r.started, Port: 1}
	}
	return bundle.Status{State: bundle.StateHealthy, StartedAt: r.started, Port: 1}
}

func (r *Runner) BaseURL() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return ""
	}
	return r.base
}

func (r *Runner) Healthy() bool                            { return r.Status().State == bundle.StateHealthy }
func (r *Runner) AdminToken(time.Duration) (string, error) { return r.admin, nil }
func (r *Runner) RemoveVolume(context.Context) error       { return nil }
func (r *Runner) RemoveImage(context.Context) error        { return nil }
func (r *Runner) SetSSRFAllowed(nets []string)             { r.mu.Lock(); r.SSRF = nets; r.mu.Unlock() }
func (r *Runner) SetEgressAllow(ap netip.AddrPort)         { r.mu.Lock(); r.Allow = ap; r.mu.Unlock() }
func (r *Runner) HostAccess(context.Context) (bundle.HostAccess, error) {
	return bundle.HostAccess{Listen: netip.MustParseAddr("127.0.0.1")}, nil
}

type verifier struct{}

func (verifier) Verify(_ context.Context, r *contextforge.LockedRelease, platform string, now time.Time) (*bundle.Verification, error) {
	return &bundle.Verification{Version: r.Version, IndexDigest: r.Image.IndexDigest, Platform: platform, PlatformDigest: r.Image.Platforms[platform],
		Issuer: r.Signer.Issuer, VerifiedAt: now}, nil
}

func (verifier) LocalDigestOK(context.Context, *bundle.Verification, string) error { return nil }
