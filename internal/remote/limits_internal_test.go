package remote

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

func TestRateKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"not-an-ip":            "not-an-ip",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"fe80::1%eth0":         "fe80::/64",
		"":                     "",
	} {
		if got := rateKey(in); got != want {
			t.Errorf("rateKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// Rotating source keys cannot grow the OAuth limiter table without bound:
// once maxTracked live keys are held, new keys share one overflow bucket.
func TestLimiterTableBounded(t *testing.T) {
	now := time.Now()
	l := newLimiters(config.RemoteLimits{OAuthPerSecond: 1, OAuthBurst: 2, ConcurrencyTotal: 1}, func() time.Time { return now })
	for i := range maxTracked {
		if ok, _ := l.allowOAuth(fmt.Sprintf("k%d", i)); !ok {
			t.Fatalf("key %d refused", i)
		}
	}
	for i := range 2 {
		if ok, _ := l.allowOAuth(fmt.Sprintf("new%d", i)); !ok {
			t.Fatalf("overflow request %d refused", i)
		}
	}
	if ok, _ := l.allowOAuth("new-third"); ok {
		t.Fatal("third new key while full was allowed; overflow keys must share one bucket")
	}
	if n := len(l.oauth); n > maxTracked+1 {
		t.Fatalf("table holds %d keys, want at most %d", n, maxTracked+1)
	}
	now = now.Add(11 * time.Minute)
	if ok, _ := l.allowOAuth("after-expiry"); !ok {
		t.Fatal("after the old keys expired a new key was refused")
	}
	if _, ok := l.oauth["after-expiry"]; !ok {
		t.Fatal("after expiry a new key should get its own bucket")
	}
}
