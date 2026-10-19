//go:build cgo

package obsstore

import (
	"database/sql"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestBatchesUseSingleThreadedInstance: store batches are copied to Parquet
// by a single-threaded DuckDB instance, so a batch runs entirely on the
// store writer's thread (at its lowered priority) and never waits for, or
// runs on, the query instance's worker thread (FR-11.4). Batches written
// this way read back through the query instance.
func TestBatchesUseSingleThreadedInstance(t *testing.T) {
	st, err := Open(Options{Dir: t.TempDir(), Backend: "duckdb", Tables: []Table{recordsV1}, MemoryLimit: 512 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := st.(*duckStore)
	setting := func(db *sql.DB, name string) string {
		var v string
		if err := db.QueryRow("SELECT current_setting('" + name + "')::VARCHAR").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if got := setting(s.w, "threads"); got != "1" {
		t.Fatalf("writer instance threads %s, want 1", got)
	}
	if got := setting(s.db, "threads"); got != "2" {
		t.Fatalf("query instance threads %s, want 2", got)
	}
	rows := fixture(40, 3)
	if err := st.Append("records", rows); err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := st.Scan("records", Filter{}, func(Row) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != len(rows) {
		t.Fatalf("read back %d rows, want %d", n, len(rows))
	}
}

// TestStatsReportMemoryAgainstBudget: the DuckDB store reports its memory
// in use and the limit its instances run with, and the limits add up to
// the configured budget exactly (FR-8.16, CP-33).
func TestStatsReportMemoryAgainstBudget(t *testing.T) {
	reqtest.Partial(t, "FR-8.16")
	for _, budget := range []int64{192 << 20, 512 << 20} {
		st, err := Open(Options{Dir: t.TempDir(), Backend: "duckdb", Tables: []Table{recordsV1}, MemoryLimit: budget})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Append("records", fixture(200, 3)); err != nil {
			t.Fatal(err)
		}
		if err := st.Scan("records", Filter{}, func(Row) error { return nil }); err != nil {
			t.Fatal(err)
		}
		s, err := st.Stats()
		st.Close()
		if err != nil {
			t.Fatal(err)
		}
		if s.Memory == nil || s.Memory.LimitBytes != budget || s.Memory.UsedBytes < 0 || s.Memory.UsedBytes > budget {
			t.Fatalf("budget %d: memory %+v", budget, s.Memory)
		}
	}
	for in, want := range map[string]int64{"192.0 MiB": 192 << 20, "1.5 GiB": 3 << 29, "0 bytes": 0, "2.0 KB": 2000} {
		if got, err := parseDuckSize(in); err != nil || got != want {
			t.Errorf("parseDuckSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseDuckSize("12 parsecs"); err == nil {
		t.Error("unknown unit accepted")
	}
}
