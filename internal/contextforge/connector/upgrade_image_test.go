package connector

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// TestUpgradeImage upgrades the bundled instance between two real pinned
// ContextForge releases (SMCP_CONTEXTFORGE_IMAGE=1, Docker, cosign):
// v1.0.10 (internal/contextforge/testdata, installed as a signed release
// lock) to v1.0.11 (the release lock of this Gateway), with an enabled
// hosted fixture package (FR-22.31). An upgrade whose new release does not
// reach health within the health wait (shortened here to one millisecond)
// restores v1.0.10, its credentials and D-16 (the instance's gateway keeps
// its ID); an unsigned lock and a lock signed with another key are
// refused; the upgrade with the normal wait verifies the v1.0.11 image,
// generates new credentials (FR-22.28), reconciles and registers the
// hosted package again, keeps it enabled and serving, installs the
// release lock and removes the v1.0.10 image.
func TestUpgradeImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge images")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed")
	}
	eng, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not installed")
	}
	plat := "linux/" + runtime.GOARCH
	newRel := contextforge.ReleaseLock().ContextForge
	oldRaw, err := os.ReadFile(filepath.Join("..", "testdata", "contextforge-v1.0.10.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldLock, err := contextforge.ParseLock(oldRaw)
	if err != nil {
		t.Fatal(err)
	}
	oldRel := oldLock.ContextForge
	h := cftest.FixtureHost(t, eng, newRel.ImageRef(plat))
	port := hostedUpstream(t, h, "get-time", "read.file")

	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	// The state an earlier upgrade to a signed v1.0.10 lock leaves.
	cfdir := filepath.Join(state, "contextforge")
	if err := os.MkdirAll(cfdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfdir, activeLockFile), oldRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfdir, activeSigFile), minisign.Sign(priv, oldRaw), 0o600); err != nil {
		t.Fatal(err)
	}
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
	c, err := New(Options{Config: cfg, Library: lib, Recorder: rec, Broker: testBroker(t, rec), Version: "test", SSRFAllowed: h.Nets,
		LockKeys: []minisign.PublicKey{pub}, EndpointFor: func(string) (string, error) { return h.URL(port), nil }})
	if err != nil {
		t.Fatal(err)
	}
	inst := c.inst.(*bundle.Instance)
	t.Cleanup(func() {
		c.Close()
		_ = inst.RemoveVolume(context.Background())
		_ = inst.DropBackup(context.Background())
		_ = inst.RemoveImageRef(context.Background(), oldRel.ImageRef(plat))
	})
	if c.lock().Version != "v1.0.10" {
		t.Fatalf("active release %s, want the installed v1.0.10 lock", c.lock().Version)
	}
	a, _ := packaging.LoadAnchors(state)
	if _, err := a.Add("contextforge-import", c.pub, []string{"moderate", "high"}, time.Now().Add(time.Hour), time.Now(), "admin"); err != nil {
		t.Fatal(err)
	}
	_ = a.Save()

	// A hosted package imported and enabled on v1.0.10.
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
	if v := c.Instance(); v.Version != "v1.0.10" || v.Image != oldRel.ImageRef(plat) {
		t.Fatalf("instance before the upgrade: %+v", v)
	}
	got, err := c.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil {
		t.Fatal(err)
	}
	rev, err := lib.Enable(got.ServerID, got.Revision, library.EnableOptions{})
	if err != nil {
		t.Fatal(err)
	}
	callTool := func(label string) {
		t.Helper()
		rt := library.NewRuntime(lib, library.RuntimeOptions{Hosted: c.ResolveHosted})
		servers, launcher, err := rt.Prepare(rec, []config.Server{{Alias: rev.Alias, Package: rev.ServerID}},
			WrapLauncher(southbound.Wrap(nil), func() *Connector { return c }), true)
		if err != nil || len(servers) != 1 {
			t.Fatalf("%s: prepare %v %+v", label, err, servers)
		}
		caps := pipeline.NewCapabilities(time.Minute)
		reg, err := backend.Start(context.Background(), servers, backend.Options{
			Limits:   backend.Limits{PerPrincipal: 2, Total: 4, Queue: 4, UpstreamTimeout: 20 * time.Second, ResultBytes: 1 << 20},
			Launcher: launcher, Manifests: rt, Capabilities: caps})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		defer reg.Close()
		ref := reg.Resolve(rev.Alias + "_read_file")
		if ref == nil {
			t.Fatalf("%s: tool not presented", label)
		}
		b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: rev.Alias + "_read_file"}
		res, err := reg.Call(context.Background(), backend.Dispatch{Principal: "p", Ref: ref, Capability: caps.Issue(b), Binding: b})
		if err != nil || res.IsError || res.Content[0].(*mcp.TextContent).Text != "ok" {
			t.Fatalf("%s: call %v %+v", label, err, res)
		}
	}
	callTool("v1.0.10")
	gatewayIDs := func() []string {
		var gws []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.admin().Call(context.Background(), http.MethodGet, "/v1/gateways?include_inactive=true", "", nil, &gws); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, g := range gws {
			ids = append(ids, g.ID)
		}
		slices.Sort(ids)
		return ids
	}
	before := gatewayIDs()
	if len(before) == 0 {
		t.Fatal("no gateway registered on v1.0.10")
	}
	credsBefore, err := c.credentials()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A new release that does not reach health in time: rolled back.
	c.o.UpgradeHealthWait = time.Millisecond
	rep, err := c.Upgrade(ctx, "op", nil, nil)
	if packaging.ReasonOf(err) != ReasonUpgradeRolledBack || rep.Step != "health" || rep.Outcome != "rolled_back" {
		t.Fatalf("health failure: %+v %v", rep, err)
	}
	waitHealthy(t, c)
	if v := c.Instance(); v.Version != "v1.0.10" || v.Image != oldRel.ImageRef(plat) {
		t.Fatalf("after the rollback: %+v", v)
	}
	if after := gatewayIDs(); !slices.Equal(after, before) {
		t.Fatalf("D-16 not restored: gateways %v, before %v", after, before)
	}
	credsBack, err := c.credentials()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range credsBefore {
		if credsBack[k] != v {
			t.Fatalf("credential %s not restored", k)
		}
	}
	if r, _ := lib.Get(rev.ServerID, rev.Revision); r.State != library.StateEnabled {
		t.Fatalf("hosted revision %s after the rollback", r.State)
	}
	if l := c.runningLock(); l == nil || l.Version != "v1.0.10" {
		t.Fatalf("running lock %+v", l)
	}

	// Unsigned, and signed with another key: refused, nothing changes.
	newRaw := contextforge.ReleaseLockJSON()
	if _, err := c.Upgrade(ctx, "op", newRaw, nil); packaging.ReasonOf(err) != ReasonUpgradeRefused || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned lock: %v", err)
	}
	_, other, _ := minisign.GenerateKey(nil)
	if _, err := c.Upgrade(ctx, "op", newRaw, minisign.Sign(other, newRaw)); packaging.ReasonOf(err) != ReasonUpgradeRefused {
		t.Fatalf("lock signed with another key: %v", err)
	}
	if v := c.Instance(); v.Version != "v1.0.10" || v.State != bundle.StateHealthy {
		t.Fatalf("after the refusals: %+v", v)
	}

	// The upgrade to this Gateway's release lock.
	c.o.UpgradeHealthWait = 0
	rep, err = c.Upgrade(ctx, "op", nil, nil)
	if err != nil {
		t.Fatalf("upgrade: %v %+v", err, rep)
	}
	t.Logf("upgraded %s to %s in %.1fs to health; hosted packages %v", rep.From, rep.To, rep.HealthSecs, rep.Packages)
	if rep.Outcome != "upgraded" || rep.From != "v1.0.10" || rep.To != newRel.Version || !slices.Equal(rep.Packages, []string{rev.Key()}) {
		t.Fatalf("report %+v", rep)
	}
	if v := c.Instance(); v.Version != newRel.Version || v.Image != newRel.ImageRef(plat) || v.State != bundle.StateHealthy || v.Verified == "" {
		t.Fatalf("after the upgrade: %+v", v)
	}
	if r, _ := lib.Get(rev.ServerID, rev.Revision); r.State != library.StateEnabled {
		t.Fatalf("hosted revision %s after the upgrade", r.State)
	}
	callTool(newRel.Version)
	credsAfter, err := c.credentials()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range credsBefore {
		if credsAfter[k] == v {
			t.Fatalf("credential %s not generated anew at the upgrade", k)
		}
	}
	if _, err := os.Stat(filepath.Join(cfdir, activeLockFile)); !os.IsNotExist(err) {
		t.Fatalf("the v1.0.10 lock is still installed: %v", err)
	}
	if l := c.runningLock(); l == nil || l.Version != newRel.Version {
		t.Fatalf("running lock %+v", l)
	}
	if out, err := exec.Command(eng, "image", "inspect", oldRel.ImageRef(plat)).CombinedOutput(); err == nil {
		t.Fatalf("the v1.0.10 image is still present: %s", out)
	}
	var outcomes []string
	for _, e := range rec.Events() {
		if e.Class == ClassInstance && strings.HasPrefix(e.Outcome, "upgrade") {
			outcomes = append(outcomes, e.Outcome)
		}
	}
	want := []string{"upgrade_started", "upgrade_rolled_back", "upgrade_refused", "upgrade_refused", "upgrade_started", "upgraded"}
	if !slices.Equal(outcomes, want) {
		t.Fatalf("events %v, want %v", outcomes, want)
	}
	reqtest.Verifies(t, "FR-22.31")
	reqtest.Partial(t, "FR-22.28", "FR-22.19")
}

func waitHealthy(t *testing.T, c *Connector) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for c.Instance().State != bundle.StateHealthy {
		if time.Now().After(deadline) {
			t.Fatalf("not healthy: %+v", c.Instance())
		}
		time.Sleep(250 * time.Millisecond)
	}
}
