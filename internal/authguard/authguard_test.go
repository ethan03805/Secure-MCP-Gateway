package authguard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

func TestRateLimitAndLockout(t *testing.T) {
	now := time.Now()
	g := New(Config{PerSourcePerMinute: 3, MaxFailures: 2, LockoutBase: time.Minute, LockoutMax: 4 * time.Minute, Now: func() time.Time { return now }})
	for i := 0; i < 3; i++ {
		if _, err := g.Check("1.2.3.4", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := g.Check("1.2.3.4", "admin"); !errors.Is(err, ErrRateLimited) || d <= 0 {
		t.Fatalf("rate limit: %v %v", d, err)
	}
	now = now.Add(time.Minute)
	g.Failure("1.2.3.4", "admin")
	g.Failure("1.2.3.4", "admin")
	if _, err := g.Check("1.2.3.4", "admin"); !errors.Is(err, ErrLocked) {
		t.Fatalf("not locked: %v", err)
	}
	// The account is locked from every source.
	if _, err := g.Check("5.6.7.8", "admin"); !errors.Is(err, ErrLocked) {
		t.Fatalf("account lock not global: %v", err)
	}
	// Backoff doubles: a third failure after the first lock locks for 2m.
	now = now.Add(61 * time.Second)
	if _, err := g.Check("5.6.7.8", "admin"); err != nil {
		t.Fatalf("lock did not expire: %v", err)
	}
	g.Failure("5.6.7.8", "admin")
	now = now.Add(90 * time.Second)
	if _, err := g.Check("9.9.9.9", "admin"); !errors.Is(err, ErrLocked) {
		t.Fatalf("backoff not doubled: %v", err)
	}
	g.Success("admin")
	if _, err := g.Check("9.9.9.9", "admin"); err != nil {
		t.Fatalf("success did not clear the account: %v", err)
	}
	// A source spraying different accounts is locked for every account.
	g.Failure("7.7.7.7", "u1")
	g.Failure("7.7.7.7", "u2")
	g.Success("u2")
	if _, err := g.Check("7.7.7.7", "u3"); !errors.Is(err, ErrLocked) {
		t.Fatalf("spraying source not locked: %v", err)
	}
}

func TestVerifyBoundedAndDummy(t *testing.T) {
	g := New(Config{VerifyConcurrency: 1, VerifyWait: 50 * time.Millisecond})
	h, _ := keys.HashPassword("pw-123456789012")
	if ok, err := g.Verify(context.Background(), h, "pw-123456789012"); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, _ := g.Verify(context.Background(), "", "anything"); ok {
		t.Fatal("unknown account matched")
	}
	// With the only slot held, a second verification gives up with ErrBusy.
	g.sem <- struct{}{}
	if _, err := g.Verify(context.Background(), h, "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
	<-g.sem
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.Verify(context.Background(), h, "x") }()
	}
	wg.Wait()
	if !EqualName("admin", "admin") || EqualName("admin", "admin2") {
		t.Fatal("EqualName")
	}
}

func TestPruneBoundsTables(t *testing.T) {
	now := time.Now()
	g := New(Config{MaxEntries: 10, Now: func() time.Time { return now }})
	for i := 0; i < 50; i++ {
		g.Check(string(rune('a'+i)), "x")
		now = now.Add(2 * time.Second)
	}
	now = now.Add(time.Hour)
	g.Prune()
	if len(g.rate) != 0 || len(g.failure) != 0 {
		t.Fatalf("tables not pruned: %d %d", len(g.rate), len(g.failure))
	}
}
