package graph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestMirrorAndExportExactlyOnceAcrossCrashes: the graph mirror feed and
// the evidence exporter both crash mid-batch over the same journal; after
// a restart of both, the mirror and the export each hold every journal
// event exactly once, with no duplicates and no gaps (SR-6.10-1).
func TestMirrorAndExportExactlyOnceAcrossCrashes(t *testing.T) {
	reqtest.Verifies(t, "SR-6.10-1")
	f := NewFake()
	cb := &crashingBackend{Fake: f}
	cb.left.Store(1 << 40)
	e := newEnv(t, cb, 50, func(c *config.Config) { c.Graph.BatchSize = 40 }, nil)
	waitReady(t, e.mirror)
	cb.left.Store(6) // allow a few mirror batches, then the feed crashes
	e.workload(120)  // 603 events, 13 segments
	deadline := time.Now().Add(10 * time.Second)
	for e.mirror.Status(context.Background(), false).State == StateReady && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	e.mirror.Close()

	// The exporter crashes while copying the fifth closed segment: the four
	// before it are exported, the fifth is a partial temporary file (what
	// a kill during the copy leaves), and the anchor is not exported.
	journalDir := filepath.Join(e.dir, "journal")
	exportDir := filepath.Join(e.dir, "export")
	errCrash := errors.New("exporter crashed")
	copies := 0
	ex := &audit.Exporter{JournalDir: journalDir, ExportDir: exportDir, BeforeCopy: func(seg string) error {
		copies++
		if copies < 5 {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(journalDir, seg))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(exportDir, "journal", "."+seg+".tmp-crash"), b[:len(b)/2], 0o600); err != nil {
			return err
		}
		return errCrash
	}}
	if _, err := ex.Sync(); !errors.Is(err, errCrash) {
		t.Fatalf("exporter did not crash: %v", err)
	}
	if _, err := os.Stat(audit.DefaultAnchorPath(filepath.Join(exportDir, "journal"))); err == nil {
		t.Fatal("anchor exported before its segments")
	}
	partial, err := audit.ReadEvents(filepath.Join(exportDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}

	// Stop the journal (its open segment is closed and anchored), then
	// restart the mirror and the exporter.
	if err := e.journal.Close(); err != nil {
		t.Fatal(err)
	}
	ids := journalIDs(t, e.dir)
	if mirrored := f.Count("AuditEvent"); mirrored >= len(ids) || len(partial) == 0 || len(partial) >= len(ids) {
		t.Fatalf("crashes did not interrupt both feeds: mirror %d, export %d of %d", mirrored, len(partial), len(ids))
	}
	cb.left.Store(1 << 40)
	m2 := e.startMirror(cb, nil)
	defer m2.Close()
	syncMirror(t, m2)
	ex2 := &audit.Exporter{JournalDir: journalDir, ExportDir: exportDir}
	res, err := ex2.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Copied) != 13-4 || !res.AnchorUpdated {
		t.Fatalf("export after restart: %+v", res)
	}

	// The mirror: one AuditEvent per journal event ID.
	if got := f.Count("AuditEvent"); got != len(ids) {
		t.Fatalf("mirror holds %d audit events, journal has %d", got, len(ids))
	}
	for _, id := range ids {
		if f.Node("AuditEvent", id) == nil {
			t.Fatalf("mirror gap: %s", id)
		}
	}
	// The export: the journal's events, each once, in order.
	exported, err := audit.ReadEvents(filepath.Join(exportDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if len(exported) != len(ids) {
		t.Fatalf("export holds %d events, journal has %d", len(exported), len(ids))
	}
	seen := map[string]bool{}
	for i, ev := range exported {
		if seen[ev.EventID] {
			t.Fatalf("export duplicate: %s", ev.EventID)
		}
		seen[ev.EventID] = true
		if ev.EventID != ids[i] {
			t.Fatalf("export event %d is %s, journal has %s", i, ev.EventID, ids[i])
		}
	}
	// Running both again changes nothing.
	if res, err := ex2.Sync(); err != nil || len(res.Copied) != 0 || res.AnchorUpdated {
		t.Fatalf("repeated export: %+v %v", res, err)
	}
	syncMirror(t, m2)
	if f.Count("AuditEvent") != len(ids) {
		t.Fatal("repeated mirror sync changed the event count")
	}
}
