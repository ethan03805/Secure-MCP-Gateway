package connector_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func instanceCreds(t *testing.T, e *cfharness.Env) map[string]string {
	t.Helper()
	var names []string
	for _, k := range bundle.CredentialKeys {
		n := strings.ReplaceAll(strings.ToLower(k), "_", "-")
		names = append(names, n)
		if _, err := e.Broker.EnsureComponent("contextforge", n, func() ([]byte, error) {
			v, err := bundle.NewCredential()
			return []byte(v), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	vals, err := e.Broker.DeliverComponent("contextforge", names)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for k, v := range vals {
		out[k] = string(v)
	}
	return out
}

// TestUpgradeWithStandIn drives the upgrade procedure of FR-22.31 against
// the ContextForge stand-in, whose runner stands for an upgradable
// instance with a D-16 that a start of another release migrates: an
// unsigned lock, a lock signed with another key and an upgrade without a
// newer release are refused; an upgrade whose new release never becomes
// healthy restores the previous release, its credentials and D-16; a
// successful upgrade to a signed lock rotates the credentials (FR-22.28),
// registers the enabled hosted package again, installs the lock and
// serves calls; and the upgrade back to this Gateway's release lock
// removes the installed lock. TestUpgradeImage runs the same procedure
// between two real releases.
func TestUpgradeWithStandIn(t *testing.T) {
	reqtest.Partial(t, "FR-22.31", "FR-22.28")
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "fx-a", URL: "https://a.example.com/mcp"}},
		LockKeys: []minisign.PublicKey{pub}, UpgradeHealthWait: 300 * time.Millisecond})
	cur := contextforge.ReleaseLock().ContextForge
	e.Runner.Release, e.Runner.Data = cur.Version, "d16"
	rev := e.Import("fx-a", connector.LocalImport{})
	g, err := e.Launch(rev)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := g.Call(rev.Alias+"_echo", map[string]any{"x": 1}); err != nil || res.IsError {
		t.Fatalf("call before: %v %+v", err, res)
	}
	oldRaw, err := os.ReadFile(filepath.Join("..", "testdata", "contextforge-v1.0.10.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	refused := func(name string, raw, sig []byte, want string) {
		t.Helper()
		rep, err := e.Conn.Upgrade(ctx, "op", raw, sig)
		if packaging.ReasonOf(err) != connector.ReasonUpgradeRefused || rep.Outcome != "refused" || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %+v %v", name, rep, err)
		}
	}
	refused("unsigned", oldRaw, nil, "not signed")
	_, other, _ := minisign.GenerateKey(nil)
	refused("other key", oldRaw, minisign.Sign(other, oldRaw), "does not verify")
	tampered := []byte(strings.Replace(string(oldRaw), "v1.0.10", "v1.0.09", 1))
	refused("tampered", tampered, minisign.Sign(other, oldRaw), "does not verify")
	refused("no newer release", nil, nil, "not newer")
	curRaw := contextforge.ReleaseLockJSON()
	refused("same release", curRaw, minisign.Sign(priv, curRaw), "already runs")

	before := instanceCreds(t, e)
	data := e.Runner.Data
	// The new release never becomes healthy: rolled back.
	e.Runner.Unhealthy = "v1.0.10"
	rep, err := e.Conn.Upgrade(ctx, "op", oldRaw, minisign.Sign(priv, oldRaw))
	if packaging.ReasonOf(err) != connector.ReasonUpgradeRolledBack || rep.Outcome != "rolled_back" || rep.Step != "health" {
		t.Fatalf("unhealthy release: %+v %v", rep, err)
	}
	if e.Runner.Release != cur.Version || e.Runner.Data != data || !e.Runner.Healthy() {
		t.Fatalf("after the rollback: release %s data %q healthy %v", e.Runner.Release, e.Runner.Data, e.Runner.Healthy())
	}
	if v := e.Conn.Instance(); v.Version != cur.Version {
		t.Fatalf("view after the rollback %+v", v)
	}
	if after := instanceCreds(t, e); !mapsEqual(after, before) {
		t.Fatal("credentials not restored")
	}
	if _, err := os.Stat(filepath.Join(e.State, "contextforge", "lock.json")); !os.IsNotExist(err) {
		t.Fatalf("the refused lock was installed: %v", err)
	}

	// The upgrade to the signed lock.
	e.Runner.Unhealthy = ""
	rep, err = e.Conn.Upgrade(ctx, "op", oldRaw, minisign.Sign(priv, oldRaw))
	if err != nil || rep.Outcome != "upgraded" || rep.Source != "signed_lock" || !slices.Equal(rep.Packages, []string{rev.Key()}) {
		t.Fatalf("upgrade: %+v %v", rep, err)
	}
	if e.Runner.Release != "v1.0.10" || !strings.HasSuffix(e.Runner.Data, "migrated@v1.0.10") {
		t.Fatalf("after the upgrade: %s %q", e.Runner.Release, e.Runner.Data)
	}
	after := instanceCreds(t, e)
	for k, v := range before {
		if after[k] == v {
			t.Fatalf("credential %s not generated anew", k)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(e.State, "contextforge", "lock.json")); err != nil || string(raw) != string(oldRaw) {
		t.Fatalf("installed lock: %v", err)
	}
	if r, _ := e.Lib.Get(rev.ServerID, rev.Revision); r.State != library.StateEnabled {
		t.Fatalf("hosted revision %s", r.State)
	}
	g2, err := e.Launch(rev)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := g2.Call(rev.Alias+"_echo", map[string]any{"x": 2}); err != nil || res.IsError {
		t.Fatalf("call after the upgrade: %v %+v", err, res)
	}
	// Back to this Gateway's release lock: the installed lock goes.
	rep, err = e.Conn.Upgrade(ctx, "op", nil, nil)
	if err != nil || rep.Outcome != "upgraded" || rep.To != cur.Version || rep.Source != "release" {
		t.Fatalf("upgrade to the release lock: %+v %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(e.State, "contextforge", "lock.json")); !os.IsNotExist(err) {
		t.Fatalf("installed lock still present: %v", err)
	}
	if !slices.Contains(e.Runner.Removed, "ghcr.io/ibm/mcp-context-forge@sha256:"+"98dfab27a38b8aa1c1d3bc02c1e911d5a3dfc230559fea22ccdffad2cfd58b6a") &&
		!slices.Contains(e.Runner.Removed, "ghcr.io/ibm/mcp-context-forge@sha256:"+"fb3c1b89e8f934b4975c17edf4b28b605b3ccf1f8830e4c6953d54757fb46a1e") {
		t.Fatalf("the previous release's image was not removed: %v", e.Runner.Removed)
	}
	var outcomes []string
	for _, ev := range e.Rec.Events() {
		if ev.Class == connector.ClassInstance && strings.HasPrefix(ev.Outcome, "upgrade") {
			outcomes = append(outcomes, ev.Outcome)
		}
	}
	want := []string{"upgrade_refused", "upgrade_refused", "upgrade_refused", "upgrade_refused", "upgrade_refused",
		"upgrade_started", "upgrade_rolled_back", "upgrade_started", "upgraded", "upgrade_started", "upgraded"}
	if !slices.Equal(outcomes, want) {
		t.Fatalf("events %v", outcomes)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
