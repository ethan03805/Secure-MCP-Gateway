package cfharness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// A complete Gateway over the harness: the full FR-4.3 request pipeline
// (session API, policy decision, filters, approvals, Tool Dispatcher,
// evidence journal) with the harness's hosted packages resolved by its
// Connector and dispatched to the ContextForge stand-in, wired as smcpd
// wires them (cmd/smcpd: southbound.Wrap inside connector.WrapLauncher,
// the library runtime with the Connector's resolver, the route decorator
// on the journal).

const (
	gwClient = "harness"
	gwSecret = "harness-secret-123"
)

// GatewayOptions configure StartGateway.
type GatewayOptions struct {
	// Ungranted are tool names (manifest names) of the revisions that the
	// policy does not grant.
	Ungranted []string
	// TOML is appended to the configuration ([limits] and the like).
	TOML string
	// Local are local servers run in process, by alias, with the tool
	// names the policy grants them.
	Local map[string]LocalServer
	// Approve approves every approval-obligated call (hosted tools have the
	// external side-effect class, whose approval floor SR-1.18-1 sets);
	// without it such calls are refused with APPROVAL_REQUIRED.
	Approve bool
}

// approveAll approves every call, as a person at the console would.
type approveAll struct{}

func (approveAll) Request(context.Context, pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	return pipeline.ApprovalResult{Outcome: pipeline.Approved, ApprovalID: "cfharness-approval", Approver: "cfharness"}, nil
}

// LocalServer is an in-process local server of StartGateway.
type LocalServer struct {
	New   func() *mcp.Server
	Tools []string
}

// FullGateway is a running Gateway over the harness.
type FullGateway struct {
	t    *testing.T
	e    *Env
	Cfg  *config.Config
	App  *app.App
	HTTP *http.Client
	RT   *library.Runtime

	mu     sync.Mutex
	events []audit.Event
	cancel context.CancelFunc
	served chan error
}

// packages is the library runtime without its Close: the harness owns the
// library.
type packages struct{ *library.Runtime }

func (packages) Close() error { return nil }

// StartGateway starts a Gateway whose [[server]] entries are the hosted
// revisions revs (imported and enabled through the harness). The policy
// grants every tool of each revision, as side effect "read" and source
// trust "untrusted", except o.Ungranted.
func (e *Env) StartGateway(o GatewayOptions, revs ...library.Revision) *FullGateway {
	t := e.t
	t.Helper()
	if err := keys.Ensure(e.State, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	port, adminPort := testport.Free(t), testport.Free(t)
	var servers, rules strings.Builder
	for _, r := range revs {
		m, _, err := e.Lib.Manifest(r.ServerID, r.Revision)
		if err != nil {
			t.Fatal(err)
		}
		var granted []string
		for _, tl := range m.Tools {
			if !contains(o.Ungranted, tl.Name) {
				granted = append(granted, tl.Name)
			}
		}
		fmt.Fprintf(&servers, "[[server]]\nalias = %q\npackage = %q\n", r.Alias, r.ServerID)
		if len(granted) > 0 {
			q, _ := json.Marshal(granted)
			fmt.Fprintf(&rules, `,{"id": "r-%s", "server": %q, "tools": %s, "side_effect": "read", "source_trust": "untrusted"}`, r.Alias, r.Alias, q)
		}
	}
	inproc := pipeline.InProcessLauncher{Servers: map[string]func() *mcp.Server{}}
	for alias, l := range o.Local {
		cmd := "/cfharness/" + alias
		inproc.Servers[cmd] = l.New
		fmt.Fprintf(&servers, "[[server]]\nalias = %q\ncommand = %q\n", alias, cmd)
		q, _ := json.Marshal(l.Tools)
		fmt.Fprintf(&rules, `,{"id": "l-%s", "server": %q, "tools": %s, "side_effect": "read", "source_trust": "trusted"}`, alias, alias, q)
	}
	hash, err := keys.HashPassword("admin password 12")
	if err != nil {
		t.Fatal(err)
	}
	secretHash, err := keys.HashPassword(gwSecret)
	if err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf(`
[listener]
address = "127.0.0.1:%d"
public_url = "https://127.0.0.1:%d"
[admin_listener]
address = "127.0.0.1:%d"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[approvals]
notify = "off"
[policy]
file = "policy.json"
[[principal]]
id = "harness"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = %q
client_secret_hash = %q
principal = "harness"
redirect_uris = ["http://localhost/unused"]
%s
%s
`, port, port, adminPort, e.State, hash, gwClient, secretHash, servers.String(), o.TOML)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := fmt.Sprintf(`{"revision": "cf-1", "framework_profiles": {"dev": {"templates": ["h"], "default_template": "h"}},
"templates": {"h": {"rules": [{"id": "none", "server": "none", "tools": ["none"]}%s]}}}`, rules.String())
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("configuration: %v\n%s", err, toml)
	}
	g := &FullGateway{t: t, e: e, Cfg: cfg, served: make(chan error, 1)}
	g.RT = library.NewRuntime(e.Lib, library.RuntimeOptions{Hosted: e.Conn.ResolveHosted})
	e.Conn.SetSuspend(g.RT.SuspendRevision)
	launcher := connector.WrapLauncher(southbound.Wrap(inproc), func() *connector.Connector { return e.Conn })
	opts := app.Options{Log: diag.Discard(), JanitorInterval: 200 * time.Millisecond, Launcher: launcher, Packages: packages{g.RT},
		Observers:    map[string]audit.Observer{"cfharness": audit.ObserverFunc(g.observe)},
		WrapInjector: func(next pipeline.SecretHeaderInjector) pipeline.SecretHeaderInjector { return e.Conn.S1Router(next) }}
	if o.Approve {
		opts.Approver = approveAll{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, opts)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	g.App, g.cancel = a, cancel
	e.Conn.SetRecorder(a.Evidence)
	a.Evidence.AddDecorator(e.Conn.Decorate)
	e.Conn.Start(ctx)
	e.Conn.RegisterRoutes(a.Admin)
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	go func() { g.served <- a.Serve(ctx) }()
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(e.State, keys.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(ca)
	g.HTTP = &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	t.Cleanup(g.Stop)
	return g
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (g *FullGateway) observe(e audit.Event) {
	g.mu.Lock()
	g.events = append(g.events, e)
	g.mu.Unlock()
}

// Events returns the journal's events so far, with Detail as JSON types.
func (g *FullGateway) Events() []audit.Event {
	g.mu.Lock()
	evs := append([]audit.Event(nil), g.events...)
	g.mu.Unlock()
	for i := range evs {
		if evs[i].Detail != nil {
			raw, _ := json.Marshal(evs[i].Detail)
			var d any
			_ = json.Unmarshal(raw, &d)
			evs[i].Detail = d
		}
	}
	return evs
}

// Stop shuts the Gateway down.
func (g *FullGateway) Stop() {
	if g.cancel == nil {
		return
	}
	g.cancel()
	select {
	case <-g.served:
	case <-time.After(15 * time.Second):
		g.t.Error("serve did not return")
	}
	g.App.Close()
	g.cancel = nil
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// Session opens a session through the session API and returns its access
// token and session ID.
func (g *FullGateway) Session() (string, string) {
	g.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, g.Cfg.Listener.PublicURL+"/smcp/v1/sessions", strings.NewReader(`{"harness_version":"cfharness","purpose":"contextforge tests"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(gwClient, gwSecret)
	r, err := g.HTTP.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil || r.StatusCode != http.StatusCreated {
		g.t.Fatalf("session API: %d %s", r.StatusCode, b)
	}
	return out["access_token"].(string), out["session_id"].(string)
}

// Client connects an MCP client in a new session and returns it with the
// session ID and its access token.
func (g *FullGateway) Client(opts *mcp.ClientOptions) (*mcp.ClientSession, string, string) {
	g.t.Helper()
	access, sid := g.Session()
	hc := &http.Client{Transport: bearer{access, g.HTTP.Transport}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "cfharness", Version: "1"}, opts).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: g.Cfg.ResourceURI(), HTTPClient: hc}, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { cs.Close() })
	return cs, sid, access
}

// Outcome is the result of one tools/call through the Gateway.
type Outcome struct {
	Res  *mcp.CallToolResult
	Code int64          // JSON-RPC error code, 0 on success
	Data map[string]any // error data
	Err  error          // a transport error
	Text string         // the text content
}

// Reason is the refusal's reason code.
func (o Outcome) Reason() string { s, _ := o.Data["reasonCode"].(string); return s }

// Correlation is the call's correlation ID: from a refusal's data, or
// for a released result the correlation of the events of the decision
// its provenance names.
func (g *FullGateway) Correlation(o Outcome) string {
	if c, ok := o.Data["correlationId"].(string); ok {
		return c
	}
	if o.Res == nil {
		return ""
	}
	p, _ := o.Res.Meta["local.smcpgw/provenance"].(map[string]any)
	dec, _ := p["decisionId"].(string)
	if dec == "" {
		return ""
	}
	for _, ev := range g.Events() {
		if ev.DecisionID == dec && ev.CorrelationID != "" {
			return ev.CorrelationID
		}
	}
	return ""
}

// Call calls a public tool name.
func (g *FullGateway) Call(cs *mcp.ClientSession, name string, args map[string]any) Outcome {
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	out := Outcome{Res: res}
	var we *jsonrpc.Error
	switch {
	case errors.As(err, &we):
		out.Code = we.Code
		_ = json.Unmarshal(we.Data, &out.Data)
	case err != nil:
		out.Err = err
	}
	if res != nil {
		var sb strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		out.Text = sb.String()
	}
	return out
}

// Operator is the control API's operator token.
func (g *FullGateway) Operator() string {
	tok, err := keys.LoadAdminToken(g.e.State)
	if err != nil {
		g.t.Fatal(err)
	}
	return tok
}
