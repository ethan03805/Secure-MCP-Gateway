//go:build linux

package analytics

import (
	"runtime"
	"testing"
)

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
