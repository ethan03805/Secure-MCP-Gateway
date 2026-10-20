package connector

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// upgRunner is an upgradable stand-in runner over the ContextForge
// stand-in's admin API.
type upgRunner struct {
	base      string
	mu        sync.Mutex
	running   bool
	started   time.Time
	release   string
	unhealthy string
	starts    []string
}

func (r *upgRunner) Start(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running, r.started = true, time.Now()
	r.starts = append(r.starts, r.release)
	return nil
}

func (r *upgRunner) Stop(context.Context) error {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
	return nil
}

func (r *upgRunner) Status() bundle.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case !r.running:
		return bundle.Status{State: bundle.StateStopped}
	case r.release == r.unhealthy:
		return bundle.Status{State: bundle.StateStarting, StartedAt: r.started}
	}
	return bundle.Status{State: bundle.StateHealthy, StartedAt: r.started}
}

func (r *upgRunner) BaseURL() string                              { return r.base }
func (r *upgRunner) Healthy() bool                                { return r.Status().State == bundle.StateHealthy }
func (r *upgRunner) AdminToken(time.Duration) (string, error)     { return "admin", nil }
func (r *upgRunner) RemoveVolume(context.Context) error           { return nil }
func (r *upgRunner) RemoveImage(context.Context) error            { return nil }
func (r *upgRunner) SetSSRFAllowed([]string)                      {}
func (r *upgRunner) SetEgressAllow(netip.AddrPort)                {}
func (r *upgRunner) BackupData(context.Context) error             { return nil }
func (r *upgRunner) RestoreData(context.Context) error            { return nil }
func (r *upgRunner) DropBackup(context.Context) error             { return nil }
func (r *upgRunner) RemoveImageRef(context.Context, string) error { return nil }
func (r *upgRunner) HostAccess(context.Context) (bundle.HostAccess, error) {
	return bundle.HostAccess{Listen: netip.MustParseAddr("127.0.0.1")}, nil
}
func (r *upgRunner) SetRelease(l *contextforge.LockedRelease) error {
	r.mu.Lock()
	r.release = l.Version
	r.mu.Unlock()
	return nil
}

type upgVerifier struct{}

func (upgVerifier) Verify(_ context.Context, r *contextforge.LockedRelease, platform string, now time.Time) (*bundle.Verification, error) {
	return &bundle.Verification{Version: r.Version, IndexDigest: r.Image.IndexDigest, Platform: platform, PlatformDigest: r.Image.Platforms[platform],
		Issuer: r.Signer.Issuer, VerifiedAt: now}, nil
}

func (upgVerifier) LocalDigestOK(context.Context, *bundle.Verification, string) error { return nil }

// TestUpgradeAtStart: the first start after a newly installed Gateway
// release (the instance last ran v1.0.10, this release pins v1.0.11) is
// the upgrade of FR-22.31, with D-16 backed up; when it fails, the
// previous release starts and the next start tries again.
func TestUpgradeAtStart(t *testing.T) {
	reqtest.Partial(t, "FR-22.31")
	si := &cftest.StandIn{AdminToken: "admin"}
	srv := httptest.NewServer(si)
	t.Cleanup(srv.Close)
	oldRaw, err := os.ReadFile(filepath.Join("..", "testdata", "contextforge-v1.0.10.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	cur := contextforge.ReleaseLock().ContextForge
	for _, fail := range []bool{true, false} {
		f := newFixture(t, "bundled = true\n")
		if err := os.WriteFile(filepath.Join(f.state, "contextforge", runningLockFile), oldRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		r := &upgRunner{base: srv.URL, release: "v1.0.10"}
		if fail {
			r.unhealthy = cur.Version
		}
		c, err := New(Options{Config: f.cfg, Library: f.lib, Recorder: f.rec, Broker: testBroker(t, f.rec), Version: "test",
			Runner: r, Verifier: upgVerifier{}, UpgradeHealthWait: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if from, to := c.pendingUpgrade(); from == nil || from.Version != "v1.0.10" || to.Version != cur.Version {
			t.Fatalf("pending upgrade %v %v", from, to)
		}
		if err := c.StartInstance(context.Background(), "op"); err != nil {
			t.Fatal(err)
		}
		var outcomes []string
		for _, e := range f.rec.Events() {
			if e.Class == ClassInstance && (e.Outcome == "upgrade_started" || e.Outcome == "upgraded" || e.Outcome == "upgrade_rolled_back" || e.Outcome == "started") {
				outcomes = append(outcomes, e.Outcome)
			}
		}
		run := c.runningLock()
		if fail {
			if !slices.Equal(outcomes, []string{"upgrade_started", "upgrade_rolled_back", "started"}) || r.release != "v1.0.10" || run.Version != "v1.0.10" {
				t.Fatalf("failed upgrade at start: %v release %s running %s", outcomes, r.release, run.Version)
			}
			// The next start of the Gateway tries again.
			c.Close()
			c2, err := New(Options{Config: f.cfg, Library: f.lib, Recorder: f.rec, Broker: testBroker(t, f.rec), Version: "test", Runner: r, Verifier: upgVerifier{}})
			if err != nil {
				t.Fatal(err)
			}
			if from, _ := c2.pendingUpgrade(); from == nil {
				t.Fatal("no pending upgrade after the rollback")
			}
			c2.Close()
			continue
		}
		if !slices.Equal(outcomes, []string{"upgrade_started", "upgraded"}) || r.release != cur.Version || run.Version != cur.Version {
			t.Fatalf("upgrade at start: %v release %s running %s", outcomes, r.release, run.Version)
		}
		if from, _ := c.pendingUpgrade(); from != nil {
			t.Fatal("still pending")
		}
		c.Close()
	}
}
