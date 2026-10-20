//go:build linux

package analytics

import (
	"context"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
)

// TestWriterRunsAtIdlePriority: the Observation Store writer's thread is
// in the SCHED_IDLE policy at nice backgroundNice while it runs.
func TestWriterRunsAtIdlePriority(t *testing.T) {
	w := newWriter(&batchStore{}, 1000, time.Hour, 10, diag.Discard())
	def := w.priority
	type result struct {
		nice   int
		policy uint32
	}
	ch := make(chan result, 1)
	w.priority = func() bool {
		ok := def()
		n, _ := threadNice()
		p, _ := threadPolicy()
		ch <- result{n, p}
		return ok
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.run(ctx); close(done) }()
	r := <-ch
	cancel()
	<-done
	if r.policy != unix.SCHED_IDLE || r.nice != backgroundNice {
		t.Fatalf("writer thread policy %d, nice %d; want SCHED_IDLE at nice %d", r.policy, r.nice, backgroundNice)
	}
}

// TestLowPriorityThread: lowPriority lowers the nice value of the calling
// goroutine's thread to backgroundNice and keeps the goroutine on it; the
// other threads keep their priority.
func TestLowPriorityThread(t *testing.T) {
	base, ok := threadNice()
	if !ok {
		t.Skip("no /proc/thread-self/stat")
	}
	type result struct {
		ok   bool
		nice int
	}
	ch := make(chan result, 1)
	go func() {
		lowered := lowPriority()
		runtime.Gosched()
		n, _ := threadNice()
		ch <- result{lowered, n}
	}()
	r := <-ch
	if !r.ok || r.nice != backgroundNice {
		t.Fatalf("lowPriority %v, thread nice %d; want %d", r.ok, r.nice, backgroundNice)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if n, _ := threadNice(); n != base {
		t.Fatalf("this thread's nice changed from %d to %d", base, n)
	}
}

// TestIdlePriorityThread: idlePriority puts the calling goroutine's thread
// in the SCHED_IDLE policy at nice backgroundNice and keeps the goroutine
// on it; the other threads keep their policy.
func TestIdlePriorityThread(t *testing.T) {
	type result struct {
		ok     bool
		nice   int
		policy uint32
	}
	ch := make(chan result, 1)
	go func() {
		idle := idlePriority()
		runtime.Gosched()
		n, _ := threadNice()
		p, _ := threadPolicy()
		ch <- result{idle, n, p}
	}()
	r := <-ch
	if !r.ok || r.policy != unix.SCHED_IDLE || r.nice != backgroundNice {
		t.Fatalf("idlePriority %v, thread policy %d, nice %d; want SCHED_IDLE at nice %d", r.ok, r.policy, r.nice, backgroundNice)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if p, _ := threadPolicy(); p == unix.SCHED_IDLE {
		t.Fatal("this thread's policy changed to SCHED_IDLE")
	}
}
