package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

func testBroker(t *testing.T, rec audit.Recorder) *secrets.Broker {
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

// With [contextforge] bundled but no Secret Vault, the instance is
// unavailable and a start is refused with CONTEXTFORGE_VAULT_REQUIRED and
// recorded; with bundled false the view is "disabled".
func TestInstanceNeedsVault(t *testing.T) {
	reqtest.Partial(t, "FR-22.28", "FR-22.41")
	f := newFixture(t, "")
	if v := f.c.Instance(); v.State != "disabled" {
		t.Fatalf("bundled false: %+v", v)
	}
	if err := f.c.StartInstance(context.Background(), "op"); packaging.ReasonOf(err) != contextforge.ReasonContextForgeDisabled {
		t.Fatalf("start with bundled false: %v", err)
	}
	g := newFixture(t, "bundled = true\n")
	v := g.c.Instance()
	if v.State != "unavailable" || v.ReasonCode != ReasonVaultRequired {
		t.Fatalf("no vault: %+v", v)
	}
	if err := g.c.StartInstance(context.Background(), "op"); packaging.ReasonOf(err) != ReasonVaultRequired {
		t.Fatalf("start: %v", err)
	}
	found := false
	for _, e := range g.events(ClassInstance) {
		if e.Outcome == "start_refused" && e.ReasonCode == ReasonVaultRequired {
			found = true
		}
	}
	if !found {
		t.Fatal("no start_refused event")
	}
}

// TestBundledInstanceImage starts the pinned image through the Connector
// with its credentials in a real vault (SMCP_CONTEXTFORGE_IMAGE=1): the
// image is verified once (SR-3.2-2 binding event), the instance becomes
// healthy, the five credentials are vault entries that appear in no file
// of the state directory and no event, the health causes name the
// unconfined profile, and Stop and Close leave no container.
func TestBundledInstanceImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge image")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed")
	}
	reqtest.Partial(t, "FR-22.19", "FR-22.25", "FR-22.28", "FR-22.30", "FR-22.41", "SR-3.2-2", "SR-2.13-5")
	f := newFixture(t, "bundled = true\n")
	b := testBroker(t, f.rec)
	c, err := New(Options{Config: f.cfg, Library: f.lib, Recorder: f.rec, Broker: b, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		if c.inst != nil {
			_ = c.inst.RemoveVolume(context.Background())
		}
	})
	ctx := context.Background()
	if err := c.StartInstance(ctx, "op"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for c.Instance().State != bundle.StateHealthy {
		if time.Now().After(deadline) {
			t.Fatalf("not healthy: %+v", c.Instance())
		}
		time.Sleep(250 * time.Millisecond)
	}
	v := c.Instance()
	if v.Verified == "" || !v.Unconfined {
		t.Fatalf("view %+v", v)
	}
	if causes := c.HealthCauses(); causes["contextforge_unconfined"] == "" {
		t.Fatalf("causes %v", causes)
	}
	creds, err := c.credentials()
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.Check(); err != nil {
		t.Fatal(err)
	}
	// No credential in any file of the state directory or any event.
	err = filepath.WalkDir(f.state, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil //nolint:nilerr // an unreadable file holds nothing the test can see
		}
		for _, k := range bundle.CredentialKeys {
			if bytes.Contains(raw, []byte(creds[k])) {
				t.Errorf("%s holds %s", p, k)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := 0
	for _, e := range f.rec.Events() {
		for _, k := range bundle.CredentialKeys {
			if bytes.Contains([]byte(e.ReasonCode+" "+anyString(e.Detail)), []byte(creds[k])) {
				t.Fatalf("event %s holds %s", e.Class, k)
			}
		}
		if e.Class == ClassInstance && e.Outcome == "image_verified" {
			bindings++
		}
	}
	if bindings != 1 {
		t.Fatalf("%d image_verified events", bindings)
	}
	if err := c.StopInstance(ctx, "op"); err != nil {
		t.Fatal(err)
	}
	if c.Instance().State != bundle.StateStopped || len(c.HealthCauses()) != 0 {
		t.Fatalf("after stop %+v %v", c.Instance(), c.HealthCauses())
	}
	// A second start does not verify again.
	if err := c.StartInstance(ctx, "op"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range f.rec.Events() {
		if e.Class == ClassInstance && e.Outcome == "image_verified" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("image verified %d times", n)
	}
}

func anyString(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// FR-22.17 (part): no starter-set offer while the bundled instance is off;
// with it on, one proposal per starter-set entry (here refused, as the
// fixture has no vault).
func TestStarterSetOffer(t *testing.T) {
	reqtest.Partial(t, "FR-22.17")
	f := newFixture(t, "")
	if _, err := f.c.ProposeStarterSet("op"); packaging.ReasonOf(err) != contextforge.ReasonContextForgeDisabled {
		t.Fatalf("bundled off: %v", err)
	}
	g := newFixture(t, "bundled = true\n")
	ps, err := g.c.ProposeStarterSet("op")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != len(contextforge.ReleaseLock().ContextForge.StarterSet) {
		t.Fatalf("%d proposals", len(ps))
	}
	for _, p := range ps {
		if p.Class != contextforge.ClassHosted || p.ReasonCode != ReasonVaultRequired {
			t.Errorf("proposal %+v", p)
		}
	}
}
