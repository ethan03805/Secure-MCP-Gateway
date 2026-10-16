package edge

import (
	"context"
	"sync"
	"time"
)

// Kinds of tracked activity.
const (
	kindRequest = iota // an HTTP request on the MCP endpoint
	kindListen         // a subscriptions/listen stream
	kindCall           // a tool call inside a request
)

type activity struct {
	kind   int
	cancel context.CancelFunc
	done   chan struct{}
}

// tracker records what each session has in progress, so that ending a
// session can cancel its calls, end its listen streams and wait for its
// requests to finish writing their responses (FR-2.11).
type tracker struct {
	mu        sync.Mutex
	seq       uint64
	bySession map[string]map[uint64]*activity
}

func newTracker() *tracker { return &tracker{bySession: map[string]map[uint64]*activity{}} }

// add registers an activity and returns the function that marks it done.
func (t *tracker) add(sessionID string, kind int, cancel context.CancelFunc) func() {
	a := &activity{kind: kind, cancel: cancel, done: make(chan struct{})}
	t.mu.Lock()
	t.seq++
	id := t.seq
	m := t.bySession[sessionID]
	if m == nil {
		m = map[uint64]*activity{}
		t.bySession[sessionID] = m
	}
	m[id] = a
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(a.done)
			t.mu.Lock()
			if m := t.bySession[sessionID]; m != nil {
				delete(m, id)
				if len(m) == 0 {
					delete(t.bySession, sessionID)
				}
			}
			t.mu.Unlock()
		})
	}
}

// take removes and returns every activity of a session.
func (t *tracker) take(sessionID string) []*activity {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.bySession[sessionID]
	delete(t.bySession, sessionID)
	out := make([]*activity, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	return out
}

func (t *tracker) count(kind int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, m := range t.bySession {
		for _, a := range m {
			if a.kind == kind {
				n++
			}
		}
	}
	return n
}

// endSession cancels calls and listen streams, then waits up to grace for
// the session's requests to finish writing. It returns the number of calls
// cancelled.
func (t *tracker) endSession(sessionID string, grace time.Duration) int {
	acts := t.take(sessionID)
	calls := 0
	for _, a := range acts {
		if a.kind == kindCall || a.kind == kindListen {
			a.cancel()
		}
		if a.kind == kindCall {
			calls++
		}
	}
	deadline := time.NewTimer(grace)
	defer deadline.Stop()
	for _, a := range acts {
		select {
		case <-a.done:
		case <-deadline.C:
			for _, b := range acts {
				b.cancel()
			}
			return calls
		}
	}
	return calls
}
