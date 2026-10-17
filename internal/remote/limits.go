package remote

import (
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// limiters hold the CP-49 rate and concurrency limits of the remote
// listener: OAuth requests per source address, tool calls per client ID,
// concurrent requests per client ID and in total.
type limiters struct {
	cfg config.RemoteLimits
	now func() time.Time

	total chan struct{}

	mu     sync.Mutex
	oauth  map[string]*bucket
	calls  map[string]*bucket
	active map[string]int
}

type bucket struct {
	l    *rate.Limiter
	last time.Time
}

const maxTracked = 10000

func newLimiters(cfg config.RemoteLimits, now func() time.Time) *limiters {
	return &limiters{cfg: cfg, now: now, total: make(chan struct{}, cfg.ConcurrencyTotal),
		oauth: map[string]*bucket{}, calls: map[string]*bucket{}, active: map[string]int{}}
}

func (l *limiters) allow(m map[string]*bucket, key string, r rate.Limit, burst int) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := m[key]
	if b == nil {
		if len(m) >= maxTracked {
			l.pruneLocked(m, now)
		}
		b = &bucket{l: rate.NewLimiter(r, burst)}
		m[key] = b
	}
	b.last = now
	res := b.l.ReserveN(now, 1)
	if !res.OK() {
		return false, time.Second
	}
	if d := res.DelayFrom(now); d > 0 {
		res.CancelAt(now)
		return false, d
	}
	return true, 0
}

// allowOAuth counts one OAuth-endpoint request from source.
func (l *limiters) allowOAuth(source string) (bool, time.Duration) {
	return l.allow(l.oauth, source, rate.Limit(l.cfg.OAuthPerSecond), l.cfg.OAuthBurst)
}

// allowCall counts one tool call of clientID.
func (l *limiters) allowCall(clientID string) (bool, time.Duration) {
	return l.allow(l.calls, clientID, rate.Limit(float64(l.cfg.CallsPerMinute)/60), l.cfg.CallsBurst)
}

// acquireTotal takes a slot of the listener-wide concurrency bound without
// waiting.
func (l *limiters) acquireTotal() bool {
	select {
	case l.total <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *limiters) releaseTotal() { <-l.total }

// acquireClient takes a per-client concurrency slot without waiting.
func (l *limiters) acquireClient(clientID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[clientID] >= l.cfg.ConcurrencyPerClient {
		return false
	}
	l.active[clientID]++
	return true
}

func (l *limiters) releaseClient(clientID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[clientID]--; l.active[clientID] <= 0 {
		delete(l.active, clientID)
	}
}

func (l *limiters) pruneLocked(m map[string]*bucket, now time.Time) {
	for k, b := range m {
		if now.Sub(b.last) > 10*time.Minute {
			delete(m, k)
		}
	}
}

func (l *limiters) prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.pruneLocked(l.oauth, now)
	l.pruneLocked(l.calls, now)
}
