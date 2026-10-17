package analytics

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
)

type tableRow struct {
	table string
	row   obsstore.Row
}

// writer batches rows into the store: a batch is written at maxRows rows or
// after interval, whichever comes first. offer never blocks; a full queue
// drops the row and counts it.
type writer struct {
	store    obsstore.Store
	maxRows  int
	interval time.Duration
	ch       chan tableRow
	syncCh   chan chan struct{}
	log      *slog.Logger

	mu        sync.Mutex
	dropCount map[string]uint64
	pressure  atomic.Uint64 // offers seen at ≥ 80% occupancy
	written   atomic.Int64
}

func newWriter(s obsstore.Store, maxRows int, interval time.Duration, queue int, log *slog.Logger) *writer {
	return &writer{store: s, maxRows: maxRows, interval: interval, ch: make(chan tableRow, queue), syncCh: make(chan chan struct{}),
		log: log, dropCount: map[string]uint64{}}
}

// sync writes every row offered before the call, or returns when ctx ends
// (the writer stopped or never ran).
func (w *writer) sync(ctx context.Context) {
	done := make(chan struct{})
	select {
	case w.syncCh <- done:
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (w *writer) offer(table string, r obsstore.Row) {
	if len(w.ch)*5 >= cap(w.ch)*4 {
		w.pressure.Add(1)
	}
	select {
	case w.ch <- tableRow{table, r}:
	default:
		w.drop(observe.DropStoreQueue, 1)
	}
}

func (w *writer) drop(reason string, n uint64) {
	w.mu.Lock()
	w.dropCount[reason] += n
	w.mu.Unlock()
}

func (w *writer) drops() map[string]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range w.dropCount {
		out[k] = v
	}
	return out
}

func (w *writer) run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	buf := map[string][]obsstore.Row{}
	n := 0
	flush := func() {
		for table, rows := range buf {
			if len(rows) == 0 {
				continue
			}
			if err := w.store.Append(table, rows); err != nil {
				w.log.Warn("observation store write failed", "table", table, "rows", len(rows), "err", err)
				w.drop(observe.DropStoreError, uint64(len(rows)))
			} else {
				w.written.Add(int64(len(rows)))
			}
			buf[table] = nil
		}
		n = 0
	}
	for {
		select {
		case <-ctx.Done():
			// Drain what is queued, then stop.
			for {
				select {
				case tr := <-w.ch:
					buf[tr.table] = append(buf[tr.table], tr.row)
				default:
					flush()
					return
				}
			}
		case tr := <-w.ch:
			buf[tr.table] = append(buf[tr.table], tr.row)
			n++
			if n >= w.maxRows {
				flush()
			}
		case <-t.C:
			flush()
		case done := <-w.syncCh:
			// Rows offered before the request are queued; take them all.
			for drained := false; !drained; {
				select {
				case tr := <-w.ch:
					buf[tr.table] = append(buf[tr.table], tr.row)
				default:
					drained = true
				}
			}
			flush()
			close(done)
		}
	}
}
