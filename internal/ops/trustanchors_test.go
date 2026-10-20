package ops

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestTrustAnchorsDuringCAFinish: the trust-anchor health check, run
// without pause while CA rotations finish, never sees the new CA with the
// old listener certificate, which would raise the integrity cause
// trust_anchor_invalid and hold the Gateway fail-closed (FR-17.8).
func TestTrustAnchorsDuringCAFinish(t *testing.T) {
	reqtest.Partial(t, "FR-17.8")
	st := t.TempDir()
	if err := keys.Ensure(st, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	check := trustAnchors(filepath.Join(st, keys.CACertFile), filepath.Join(st, keys.ServerCertFile))
	if cs := check(time.Now()); len(cs) != 0 {
		t.Fatalf("fresh state: %+v", cs)
	}
	var stop atomic.Bool
	var bad atomic.Value
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				for _, c := range check(time.Now()) {
					if c.Name == health.CauseTrustInvalid {
						bad.Store(c.Detail)
					}
				}
			}
		}()
	}
	for i := 0; i < 15; i++ {
		if _, _, err := keys.BeginCARotation(st, time.Now(), time.Hour, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		if _, err := keys.FinishCARotation(st, time.Now(), "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if d := bad.Load(); d != nil {
		t.Fatalf("trust_anchor_invalid during a CA rotation: %v", d)
	}
}
