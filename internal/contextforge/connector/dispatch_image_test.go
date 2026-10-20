package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// TestHostedDispatchImage runs a hosted package end to end through the
// pinned image (SMCP_CONTEXTFORGE_IMAGE=1, Docker): import, enable, resolution by the Connector at
// launch (team, user, gateway, virtual server, token, scope self-check),
// a call through the Tool Dispatcher over the southbound Streamable HTTP
// transport with the package token, under the backend name; then a tool
// removed behind the Gateway's back: the call fails as a -32601 backend
// error instead of relaying ContextForge's "Unknown tool" text, and the
// reconciliation it starts suspends the revision.
func TestHostedDispatchImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge image")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed")
	}
	eng, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not installed")
	}
	reqtest.Partial(t, "FR-22.29", "FR-22.33", "FR-22.34", "FR-22.35", "FR-22.36", "SR-2.10-2", "SR-3.8-2")
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	h := cftest.FixtureHost(t, eng, img)
	nets := h.Nets
	port := hostedUpstream(t, h, "get-time", "read.file")

	state := t.TempDir()
	catalog := []byte("catalog_servers:\n  - id: fixture-hosted\n    name: Fixture hosted\n    provider: Example\n    auth_type: Open\n    url: https://hosted.example/mcp\n")
	file := filepath.Join(t.TempDir(), "catalog.yml")
	if err := os.WriteFile(file, catalog, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf("[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[state]\ndir = %q\n[approvals]\nnotify = \"off\"\n[contextforge]\nbundled = true\ncatalog_file = %q\ncatalog_sha256 = %q\n",
		state, file, packaging.SHA256Hex(catalog))))
	if err != nil {
		t.Fatal(err)
	}
	lib, err := library.Open(library.Options{StateDir: state, HostedAllowed: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	rec := &audit.Memory{}
	lib.SetRecorder(rec)
	c, err := New(Options{Config: cfg, Library: lib, Recorder: rec, Broker: testBroker(t, rec), Version: "test", SSRFAllowed: nets,
		EndpointFor: func(string) (string, error) { return h.URL(port), nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		if c.inst != nil {
			_ = c.inst.RemoveVolume(context.Background())
		}
	})
	a, _ := packaging.LoadAnchors(state)
	if _, err := a.Add("contextforge-import", c.pub, []string{"moderate", "high"}, time.Now().Add(time.Hour), time.Now(), "admin"); err != nil {
		t.Fatal(err)
	}
	_ = a.Save()

	// Import and enable the hosted package.
	p, err := c.ProposeLocal("fixture-hosted", LocalImport{}, "op")
	if err != nil {
		t.Fatal(err)
	}
	for p.State == stateBuilding {
		time.Sleep(250 * time.Millisecond)
		p, _ = c.Proposal(p.ID)
	}
	if p.State != stateReady {
		t.Fatalf("probe: %s %s", p.ReasonCode, p.Error)
	}
	got, err := c.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil {
		t.Fatal(err)
	}
	rev, err := lib.Enable(got.ServerID, got.Revision, library.EnableOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Launch through the library runtime, the Connector's resolver and
	// launcher wrapper, and the southbound transport.
	rt := library.NewRuntime(lib, library.RuntimeOptions{Hosted: c.ResolveHosted})
	c.o.Suspend = rt.SuspendRevision
	servers, launcher, err := rt.Prepare(rec, []config.Server{{Alias: rev.Alias, Package: rev.ServerID}},
		WrapLauncher(southbound.Wrap(nil), func() *Connector { return c }), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || !strings.HasPrefix(servers[0].URL, c.inst.BaseURL()+"/servers/") {
		t.Fatalf("resolved %+v; bindings %+v", servers, rt.Bindings())
	}
	sctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	c.Start(sctx)
	caps := pipeline.NewCapabilities(time.Minute)
	reg, err := backend.Start(context.Background(), servers, backend.Options{
		Limits:   backend.Limits{PerPrincipal: 2, Total: 4, Queue: 4, UpstreamTimeout: 20 * time.Second, ResultBytes: 1 << 20},
		Launcher: launcher, Manifests: rt, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	rt.Started(func(alias, reason string) bool { return reg.Suspend(alias, reason) })
	call := func(public string) (*mcp.CallToolResult, error) {
		ref := reg.Resolve(public)
		if ref == nil {
			for _, e := range rec.Events() {
				if e.Outcome == "suspended" || e.Outcome == "not_started" || strings.Contains(e.Outcome, "drift") {
					t.Logf("event %s %s %s %v", e.Class, e.Outcome, e.ReasonCode, e.Detail)
				}
			}
			t.Logf("servers %v bindings %+v", reg.Servers(), rt.Bindings())
			return nil, errors.New("not presented: " + public)
		}
		b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: public}
		return reg.Call(context.Background(), backend.Dispatch{Principal: "p", Ref: ref, Capability: caps.Issue(b), Binding: b})
	}
	res, err := call(rev.Alias + "_read_file")
	if err != nil {
		t.Fatalf("hosted call: %v", err)
	}
	if res.IsError || len(res.Content) == 0 || res.Content[0].(*mcp.TextContent).Text != "ok" {
		t.Fatalf("hosted result %+v", res)
	}

	// FR-22.35: a harness's or agent's credential (an opaque Gateway
	// access token, and a JWT of another issuer) is refused on every
	// path of the running instance.
	c.hostedMu.Lock()
	var vsID string
	for id := range c.hosted {
		vsID = id
	}
	c.hostedMu.Unlock()
	agentJWT, _ := bundle.SignJWT("an-agent-signing-key-of-32-bytes-or-more", map[string]any{"sub": "agent", "iss": "smcp", "aud": "smcp",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	for _, tok := range []string{"smcp_at_0123456789abcdef0123456789abcdef", agentJWT} {
		for _, path := range []string{"/servers/" + vsID + "/mcp", "/mcp", "/rpc", "/v1/tools"} {
			req, _ := http.NewRequest(http.MethodPost, c.inst.BaseURL()+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("the instance answered %d to an agent credential on %s", resp.StatusCode, path)
			}
		}
	}

	// The tool taken off the package's virtual server behind the Gateway's
	// back (ContextForge v1.0.11 fails to delete a federated tool from its
	// SQLite store, so the server's tool set is changed instead).
	tools, err := c.admin().Tools(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var keep []string
	for _, tl := range tools {
		if !strings.HasSuffix(tl.Name, "-get-time") {
			keep = append(keep, tl.ID)
		}
	}
	c.hostedMu.Lock()
	var vs string
	for id := range c.hosted {
		vs = id
	}
	c.hostedMu.Unlock()
	if err := c.admin().Call(context.Background(), http.MethodPut, "/v1/servers/"+vs, "", map[string]any{"associated_tools": keep}, nil); err != nil {
		t.Fatal(err)
	}
	_, err = call(rev.Alias + "_get_time")
	var be *backend.BackendError
	if !errors.As(err, &be) || be.Code != -32601 {
		t.Fatalf("removed tool: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		r, _ := lib.Get(rev.ServerID, rev.Revision)
		if r.State == library.StateSuspended {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revision %s, want suspended after the reconciliation", r.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
	drift := 0
	for _, e := range rec.Events() {
		if e.Class == ClassDrift {
			drift++
		}
	}
	if drift == 0 {
		t.Fatal("no contextforge_drift event")
	}
}
