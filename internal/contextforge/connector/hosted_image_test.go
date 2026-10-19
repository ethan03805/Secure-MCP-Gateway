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
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// hostedUpstream is a hosted MCP server fixture on the host's loopback
// with tool names that need the FR-22.10 mapping.
func hostedUpstream(t *testing.T, names ...string) string {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "fx-hosted", Version: "2.0.0"}, nil)
	// ContextForge serves "get_time" and "get-time" under one name (it
	// turns underscores into hyphens), so a fixture with both is refused
	// with TOOL_NAME_COLLISION; these three are served apart.
	for _, n := range names {
		mcp.AddTool(s, &mcp.Tool{Name: n, Description: "Fixture " + n + "."}, func(_ context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = "127.0.0.1"; h.ServeHTTP(w, r) }), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// TestHostedImportImage imports a hosted entry through the pinned image
// (SMCP_CONTEXTFORGE_IMAGE=1, Docker with host.docker.internal): the probe
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
	reqtest.Partial(t, "FR-22.9", "FR-22.10", "FR-22.11", "FR-22.12", "FR-22.13", "FR-22.23", "FR-22.32")
	eng, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not installed")
	}
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	py := "import socket,ipaddress\nfor a in sorted({x[4][0] for x in socket.getaddrinfo('host.docker.internal',None)}):\n print(a+('/32' if ipaddress.ip_address(a).version==4 else '/128'))"
	out, err := exec.Command(eng, "run", "--rm", "--entrypoint", "python3", img, "-c", py).CombinedOutput()
	if err != nil {
		t.Skipf("host.docker.internal is not resolvable: %s", out)
	}
	nets := strings.Fields(string(out))
	port := hostedUpstream(t, "get-time", "read.file", strings.Repeat("long-name-", 6))
	dupPort := hostedUpstream(t, "get-time", "get_time")

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
				return "http://host.docker.internal:" + dupPort + "/mcp", nil
			}
			return "http://host.docker.internal:" + port + "/mcp", nil
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
	m, _, err := lib.Manifest(got.ServerID, got.Revision)
	if err != nil {
		t.Fatal(err)
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
	if _, err := lib.Enable(got.ServerID, got.Revision, library.EnableOptions{}); err != nil {
		t.Fatal(err)
	}
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
	if rep.CredentialsRetired != 5 || !rep.VolumeRemoved || len(rep.Suspended) != 1 {
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
