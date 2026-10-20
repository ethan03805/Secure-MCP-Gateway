package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// hostedUpstream is a hosted MCP server fixture on the host (where
// cftest.FixtureHost says the container reaches it)
// with tool names that need the FR-22.10 mapping.
var (
	upstreamMu    sync.Mutex
	upstreamCalls = map[string][]string{} // fixture port -> tool names called
)

// calledOn returns the tool names the fixture on port was called with.
func calledOn(port string) []string {
	upstreamMu.Lock()
	defer upstreamMu.Unlock()
	return append([]string(nil), upstreamCalls[port]...)
}

func hostedUpstream(t *testing.T, host cftest.Host, names ...string) string {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "fx-hosted", Version: "2.0.0"}, nil)
	var port string
	// ContextForge serves "get_time" and "get-time" under one name (it
	// turns underscores into hyphens), so a fixture with both is refused
	// with TOOL_NAME_COLLISION; these three are served apart.
	for _, n := range names {
		mcp.AddTool(s, &mcp.Tool{Name: n, Description: "Fixture " + n + "."}, func(_ context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
			upstreamMu.Lock()
			upstreamCalls[port] = append(upstreamCalls[port], n)
			upstreamMu.Unlock()
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	l, err := net.Listen("tcp", net.JoinHostPort(host.Listen, "0"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = "127.0.0.1"; h.ServeHTTP(w, r) }), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port
}

// TestHostedImportImage imports a hosted entry through the pinned image
// (SMCP_CONTEXTFORGE_IMAGE=1, Docker): the probe
// registers the entry in the bundled instance, reads the served tools with
// the package's own token and removes its objects; the manifest_version 2
// package maps the names as FR-22.10 states, every tool is untrusted, the
// decision states that the code cannot be inspected, and the accepted
// package is imported disabled under SR-3-6.
func TestHostedImportImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge image")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed")
	}
	reqtest.Partial(t, "FR-22.9", "FR-22.11", "FR-22.12", "FR-22.13", "FR-22.23", "FR-22.32")
	eng, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not installed")
	}
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	h := cftest.FixtureHost(t, eng, img)
	nets := h.Nets
	port := hostedUpstream(t, h, "get-time", "read.file", strings.Repeat("long-name-", 6))
	dupPort := hostedUpstream(t, h, "get-time", "get_time")

	state := t.TempDir()
	catalog := []byte("catalog_servers:\n  - id: fixture-hosted\n    name: Fixture hosted\n    provider: Example\n    auth_type: Open\n    url: https://hosted.example/mcp\n    description: A hosted fixture.\n" +
		"  - id: fixture-dup\n    name: Fixture duplicate names\n    provider: Example\n    auth_type: Open\n    url: https://dup.example/mcp\n")
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
	var clock time.Time
	now := func() time.Time {
		if clock.IsZero() {
			return time.Now()
		}
		return clock
	}
	c, err := New(Options{Config: cfg, Library: lib, Recorder: rec, Broker: testBroker(t, rec), Version: "test", SSRFAllowed: nets, Now: now,
		EndpointFor: func(u string) (string, error) {
			if strings.Contains(u, "dup.example") {
				return h.URL(dupPort), nil
			}
			return h.URL(port), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		if c.inst != nil {
			_ = c.inst.RemoveVolume(context.Background())
		}
	})
	// FR-22.10: an operator's choice of the risk class low is refused.
	if _, err := c.ProposeLocal("fixture-hosted", LocalImport{RiskClass: "low"}, "op"); err == nil || !strings.Contains(err.Error(), `"low"`) {
		t.Fatalf("risk class low: %v", err)
	}
	p, err := c.ProposeLocal("fixture-hosted", LocalImport{}, "op")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Minute)
	for p.State == stateBuilding {
		if time.Now().After(deadline) {
			t.Fatal("probe still running")
		}
		time.Sleep(250 * time.Millisecond)
		p, _ = c.Proposal(p.ID)
	}
	if p.State != stateReady {
		t.Fatalf("probe: %s %s", p.ReasonCode, p.Error)
	}
	if !strings.Contains(p.Decision.Text, "cannot be inspected") || !p.Decision.Fields.NotInspected || len(p.Decision.Fields.Tools) != 3 {
		t.Fatalf("decision %+v", p.Decision)
	}
	// The probe objects are gone from the instance.
	if tools, err := c.admin().Tools(context.Background(), ""); err != nil || len(tools) != 0 {
		t.Fatalf("probe objects left: %v %v", tools, err)
	}
	// Enroll the import key and accept.
	a, _ := packaging.LoadAnchors(state)
	if _, err := a.Add("contextforge-import", c.pub, []string{"moderate", "high"}, time.Now().Add(time.Hour), time.Now(), "admin"); err != nil {
		t.Fatal(err)
	}
	_ = a.Save()
	got, err := c.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil || got.Outcome != "imported" {
		t.Fatalf("accept: %v %+v", err, got)
	}
	m, mraw, err := lib.Manifest(got.ServerID, got.Revision)
	if err != nil {
		t.Fatal(err)
	}
	// FR-22.10: the written manifest against the manifest_version 2
	// schema, its upstream member, and the name derivation, which does not
	// depend on the order of the probed tools.
	pm, err := packaging.ParseManifest(mraw)
	if err != nil || pm.ManifestVersion != 2 {
		t.Fatalf("manifest against the version 2 schema: %v", err)
	}
	up := m.Upstream
	if up == nil || up.Kind != "contextforge-hosted" || up.Transport == "" || up.EntryID != "fixture-hosted" || up.EntrySHA256 == "" ||
		up.GatewayName != "smcp-fixture-hosted" || up.GatewaySlug != "smcp-fixture-hosted" || m.ToolsListSHA256 == "" {
		t.Fatalf("upstream %+v tools_list_sha256 %q", up, m.ToolsListSHA256)
	}
	var backends []string
	for _, tl := range m.Tools {
		backends = append(backends, tl.BackendName)
	}
	fwd, err := contextforge.MapToolNames(up.GatewaySlug, backends)
	if err != nil {
		t.Fatal(err)
	}
	reversedNames := append([]string(nil), backends...)
	slices.Reverse(reversedNames)
	back, err := contextforge.MapToolNames(up.GatewaySlug, reversedNames)
	if err != nil {
		t.Fatal(err)
	}
	derived, reversed := map[string]string{}, map[string]string{}
	for _, n := range fwd {
		derived[n.BackendName] = n.Name
	}
	for _, n := range back {
		reversed[n.BackendName] = n.Name
	}
	for _, tl := range m.Tools {
		if derived[tl.BackendName] != tl.Name || reversed[tl.BackendName] != tl.Name {
			t.Errorf("tool %s (%s): derived %q, reverse order %q", tl.Name, tl.BackendName, derived[tl.BackendName], reversed[tl.BackendName])
		}
	}
	want := map[string]string{"read_file": "smcp-fixture-hosted-read-file"}
	for _, tl := range m.Tools {
		if tl.SourceTrust != "untrusted" || !manifestName(tl.Name) {
			t.Errorf("tool %+v", tl)
		}
		if w, ok := want[tl.Name]; ok && tl.BackendName != w {
			t.Errorf("%s backend %s, want %s", tl.Name, tl.BackendName, w)
		}
	}
	if !m.Hosted() || m.Upstream.GatewayName != "smcp-fixture-hosted" || m.Upstream.URL != "https://hosted.example/mcp" || len(m.Tools) != 3 {
		t.Fatalf("manifest %+v", m)
	}
	raw, _ := os.ReadFile(filepath.Join(lib.Dir(), got.ServerID, got.Revision, packaging.ProvenanceFile))
	var pv packaging.Provenance
	_ = json.Unmarshal(raw, &pv)
	if pv.ContextForge == nil || pv.ContextForge.InstanceDigest == "" || pv.ContextForge.ProbedAt == "" || pv.TrustDecision == nil {
		t.Fatalf("provenance %+v", pv)
	}
	rev, _ := lib.Get(got.ServerID, got.Revision)
	if rev.State != library.StateVerifiedDisabled {
		t.Fatalf("state %s", rev.State)
	}
	// get-time and get_time are served under one name: refused.
	d, err := c.ProposeLocal("fixture-dup", LocalImport{}, "op")
	if err != nil {
		t.Fatal(err)
	}
	for d.State == stateBuilding {
		time.Sleep(250 * time.Millisecond)
		d, _ = c.Proposal(d.ID)
	}
	if d.State != stateFailed || d.ReasonCode != contextforge.ReasonToolNameCollision || !strings.Contains(d.Error, "get-time") {
		t.Fatalf("duplicate names: %s %s %s", d.State, d.ReasonCode, d.Error)
	}
	// FR-22.23: an enabled hosted revision keeps the instance running; it
	// stops IdleStop after the last one is disabled. FR-22.32: uninstall.
	ctx := context.Background()
	enabled, err := lib.Enable(got.ServerID, got.Revision, library.EnableOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// FR-22.10: a call to each tool reaches the fixture under its
	// backend name.
	rt := library.NewRuntime(lib, library.RuntimeOptions{Hosted: c.ResolveHosted})
	servers, launcher, err := rt.Prepare(rec, []config.Server{{Alias: enabled.Alias, Package: enabled.ServerID}},
		WrapLauncher(southbound.Wrap(nil), func() *Connector { return c }), true)
	if err != nil || len(servers) != 1 {
		t.Fatalf("prepare: %v %+v", err, servers)
	}
	caps := pipeline.NewCapabilities(time.Minute)
	reg, err := backend.Start(ctx, servers, backend.Options{
		Limits:   backend.Limits{PerPrincipal: 2, Total: 4, Queue: 4, UpstreamTimeout: 20 * time.Second, ResultBytes: 1 << 20},
		Launcher: launcher, Manifests: rt, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range m.Tools {
		public := enabled.Alias + "_" + tl.Name
		ref := reg.Resolve(public)
		if ref == nil {
			t.Fatalf("%s not presented", public)
		}
		b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: public}
		if res, err := reg.Call(ctx, backend.Dispatch{Principal: "p", Ref: ref, Capability: caps.Issue(b), Binding: b}); err != nil || res.IsError {
			t.Fatalf("call %s: %v %+v", public, err, res)
		}
	}
	reg.Close()
	calls := calledOn(port)
	slices.Sort(calls)
	wantCalls := []string{"get-time", strings.Repeat("long-name-", 6), "read.file"}
	slices.Sort(wantCalls)
	if !slices.Equal(calls, wantCalls) {
		t.Fatalf("the fixture was called with %v, want %v", calls, wantCalls)
	}
	reqtest.Verifies(t, "FR-22.10")
	clock = time.Now()
	c.onDemand(ctx)
	if !c.inst.Healthy() {
		t.Fatalf("instance not running with an enabled hosted revision: %+v", c.inst.Status())
	}
	if _, _, err := lib.SetState(got.ServerID, got.Revision, library.StateVerifiedDisabled, "test", "op"); err != nil {
		t.Fatal(err)
	}
	c.onDemand(ctx)
	if c.inst.Status().State == "stopped" {
		t.Fatal("stopped at once, not after the idle period")
	}
	clock = clock.Add(IdleStop)
	c.onDemand(ctx)
	if st := c.inst.Status().State; st != "stopped" {
		t.Fatalf("still %s %v after the last hosted revision was disabled", st, IdleStop)
	}
	clock = time.Time{}
	if _, err := lib.Enable(got.ServerID, got.Revision, library.EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	rep, err := c.Uninstall(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// The five instance credentials and the package user's password.
	if rep.CredentialsRetired != 6 || !rep.VolumeRemoved || len(rep.Suspended) != 1 {
		t.Fatalf("uninstall %+v", rep)
	}
	if r, _ := lib.Get(got.ServerID, got.Revision); r.State != library.StateSuspended {
		t.Fatalf("hosted revision %s after uninstall", r.State)
	}
}

func manifestName(s string) bool {
	if len(s) == 0 || len(s) > 47 {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
