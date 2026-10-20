package bundle

import (
	"context"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// upstream is a hosted-server fixture: a Streamable HTTP MCP server on the
// host (where cftest.FixtureHost says the container reaches it) that counts
// tool calls.
type upstream struct {
	port  string
	calls atomic.Int32
}

func newUpstream(t *testing.T, host cftest.Host, name string) *upstream {
	t.Helper()
	u := &upstream{}
	s := mcp.NewServer(&mcp.Implementation{Name: "fx-" + name, Version: "1"}, nil)
	for _, n := range []string{"get-time", "echo"} {
		mcp.AddTool(s, &mcp.Tool{Name: n, Description: name + " " + n}, func(_ context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
			u.calls.Add(1)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: name + " answered"}}}, nil, nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	l, err := net.Listen("tcp", net.JoinHostPort(host.Listen, "0"))
	if err != nil {
		t.Fatal(err)
	}
	// The container reaches the host by name; the SDK's DNS-rebinding
	// guard wants a loopback Host, as the E-18 endpoint would send.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = "127.0.0.1"; h.ServeHTTP(w, r) }), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, u.port, _ = net.SplitHostPort(l.Addr().String())
	return u
}

// TestIsolationImage provisions two hosted packages in the pinned image
// (SMCP_CONTEXTFORGE_IMAGE=1, Docker) and runs
// the scope self-check: with each package's token, /mcp and /rpc list only
// its own tools, the other package's tool cannot be called through its
// virtual server, /mcp or /rpc, its fixture records no call, and admin
// routes refuse the token. Then a leaking set-up as the spike found it (an
// administrator-owned token restricted only by scope.server_id and a
// gateway without team visibility) is reported by the self-check.
func TestIsolationImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge image")
	}
	reqtest.Partial(t, "FR-22.29", "FR-22.34", "FR-22.38")
	eng, err := FindEngine()
	if err != nil {
		t.Skip(err)
	}
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	h := cftest.FixtureHost(t, eng.Path, img)
	nets := h.Nets
	creds, _ := NewCredentials()
	in, err := New(Options{Engine: eng, Image: img, Name: "smcp-cf-test-isolation",
		Settings:    Settings{SSRFAllowed: nets, Limits: Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}},
		Credentials: func() (Credentials, error) { return creds, nil }, HealthWait: 120 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = in.Stop(ctx); _ = in.RemoveVolume(ctx) })
	if err := in.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for !in.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("not healthy")
		}
		time.Sleep(200 * time.Millisecond)
	}
	a := &Admin{Base: in.BaseURL(), AdminToken: func() (string, error) { return in.AdminToken(5 * time.Minute) }}
	ua, ub := newUpstream(t, h, "A"), newUpstream(t, h, "B")
	pkgs := map[string]*Provisioned{}
	for name, u := range map[string]*upstream{"smcp-pkg-a": ua, "smcp-pkg-b": ub} {
		pw, _ := NewCredential()
		p, err := a.Provision(ctx, PackageSpec{Slug: name, URL: h.URL(u.port)}, pw)
		if err != nil {
			t.Fatalf("provision %s: %v", name, err)
		}
		if len(p.Tools) != 2 || p.Token == "" || time.Until(p.Expires) > 25*time.Hour {
			t.Fatalf("provisioned %+v", p)
		}
		pkgs[name] = p
	}
	pa, pb := pkgs["smcp-pkg-a"], pkgs["smcp-pkg-b"]
	if f := a.SelfCheck(ctx, []*Provisioned{pa, pb}); len(f) != 0 {
		t.Fatalf("isolated set-up has findings: %+v", f)
	}
	if n := ub.calls.Load() + ua.calls.Load(); n != 0 {
		t.Fatalf("fixtures recorded %d calls during the self-check", n)
	}
	// Own tools are listed and callable through the package's own virtual
	// server (the path E-10 uses, FR-22.34).
	names, st, err := a.listTools(ctx, "/servers/"+pa.ServerID+"/mcp", pa.Token)
	if err != nil || st != http.StatusOK || len(names) != 2 {
		t.Fatalf("own virtual server: %v %d %v", names, st, err)
	}
	if reached, _ := a.callReaches(ctx, "/servers/"+pa.ServerID+"/mcp", pa.Token, pa.Tools[0]); !reached || ua.calls.Load() != 1 {
		t.Fatalf("own tool not callable (calls %d)", ua.calls.Load())
	}

	// The leaking set-up: a gateway in no team and an administrator-owned
	// token restricted only by scope.server_id.
	uc := newUpstream(t, h, "C")
	if err := a.Call(ctx, http.MethodPost, "/v1/gateways", "", map[string]any{"name": "smcp-leak-c", "url": h.URL(uc.port),
		"transport": "STREAMABLEHTTP", "visibility": "public"}, nil); err != nil {
		t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := a.Call(ctx, http.MethodPost, "/v1/tokens", "", map[string]any{"name": "admin-scoped", "expires_in_days": 1, "scope": map[string]any{"server_id": pa.ServerID}}, &tok); err != nil {
		t.Fatal(err)
	}
	leaky := *pa
	leaky.Token = tok.AccessToken
	tools, err := a.Tools(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	pc := &Provisioned{Slug: "smcp-leak-c"}
	for _, tl := range tools {
		if tl.GatewaySlug == "smcp-leak-c" {
			pc.Tools = append(pc.Tools, tl.Name)
		}
	}
	findings := a.SelfCheck(ctx, []*Provisioned{&leaky, pb, pc})
	leaked := false
	for _, f := range findings {
		if f.Package == pa.Slug && (strings.Contains(f.Probe, "/mcp") || strings.Contains(f.Probe, "/rpc")) {
			leaked = true
		}
	}
	if !leaked {
		t.Fatalf("the leaking set-up was not found: %+v", findings)
	}
	t.Logf("leaking set-up findings: %d (for example %+v)", len(findings), findings[0])
}
