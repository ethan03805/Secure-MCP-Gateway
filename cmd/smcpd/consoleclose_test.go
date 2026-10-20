package main

import (
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestConsoleCloseHandling: a console close, logoff or shutdown event (on
// Windows delivered as SIGTERM) records the stop in the journal first and
// then exits 0; a journal that does not finish within the budget does not
// keep the process past it (exit 1), and the budget leaves Windows' 5
// seconds a margin, so smcpd exits within 4 seconds (FR-21.7). The
// delivery of the real CTRL_CLOSE, CTRL_LOGOFF and CTRL_SHUTDOWN events,
// which no process can send to another, is not tested; the console
// CTRL_BREAK stop is tested end to end on Windows
// (internal/acceptance.TestWindowsConsoleStop).
func TestConsoleCloseHandling(t *testing.T) {
	reqtest.Partial(t, "FR-21.7")
	if consoleCloseBudget >= 4*time.Second {
		t.Fatalf("budget %v leaves no margin within 4 seconds", consoleCloseBudget)
	}
	type result struct {
		order []string
		at    time.Duration
	}
	run := func(record func()) result {
		var mu sync.Mutex
		var r result
		done := make(chan struct{})
		ch := make(chan os.Signal, 1)
		start := time.Now()
		var once sync.Once
		go onConsoleClose(ch, func() {
			record()
			mu.Lock()
			r.order = append(r.order, "recorded")
			mu.Unlock()
		}, func(code int) {
			mu.Lock()
			r.order = append(r.order, map[int]string{0: "exit 0", 1: "exit 1"}[code])
			if r.at == 0 {
				r.at = time.Since(start)
			}
			mu.Unlock()
			once.Do(func() { close(done) })
		}, 200*time.Millisecond)
		ch <- syscall.SIGTERM
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("no exit within 5 seconds")
		}
		mu.Lock()
		defer mu.Unlock()
		return result{order: append([]string(nil), r.order...), at: r.at}
	}

	// The journal answers: the stop is recorded, then the process exits 0.
	r := run(func() {})
	if len(r.order) != 2 || r.order[0] != "recorded" || r.order[1] != "exit 0" {
		t.Fatalf("order %v, want [recorded exit 0]", r.order)
	}
	// The journal hangs: the process exits 1 at the budget.
	block := make(chan struct{})
	defer close(block)
	r = run(func() { <-block })
	if len(r.order) == 0 || r.order[0] != "exit 1" || r.at < 200*time.Millisecond || r.at > 2*time.Second {
		t.Fatalf("hung journal: %v after %v, want exit 1 at the budget", r.order, r.at)
	}
}
