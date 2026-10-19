//go:build cgo

package obsstore

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func parquetFiles(t *testing.T, dir, table, day string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, table, "day="+day, "*.parquet"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func snapshot(t *testing.T, s Store) ([]AggRow, int) {
	t.Helper()
	agg, err := s.Aggregate(AggQuery{Feature: "request_bytes", GroupBy: []string{"tool_name"}, Bucket: time.Hour, Quantiles: []float64{0.5, 0.95}})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := s.Scan("records", Filter{}, func(Row) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	return agg, n
}

// TestCompactMergesSmallFiles: a partition with at least CompactFiles
// batch files is merged into one file, a partition with fewer is left
// alone, and every query answers as before; files of different schema
// versions merge by column name.
func TestCompactMergesSmallFiles(t *testing.T) {
	dir := t.TempDir()
	s := open(t, "duckdb", dir, recordsV1)
	rows := fixture(2000, 9) // 48 hours from day0: two partitions
	day1 := rows[:1000]
	for i := 0; i < len(day1); i += 50 { // 20 batches into day0
		if err := s.Append("records", day1[i:i+50]); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1000; i < 1000+5*50; i += 50 { // 5 batches into day0+1
		if err := s.Append("records", rows[i:i+50]); err != nil {
			t.Fatal(err)
		}
	}
	d0, d1 := DayOf(day0), DayOf(day0.Add(24*time.Hour))
	if n := len(parquetFiles(t, dir, "records", d0)); n != 20 {
		t.Fatalf("%d files before compaction", n)
	}
	beforeAgg, beforeN := snapshot(t, s)
	merged, err := s.(Compactor).Compact()
	if err != nil {
		t.Fatal(err)
	}
	if merged != 20 || len(parquetFiles(t, dir, "records", d0)) != 1 || len(parquetFiles(t, dir, "records", d1)) != 5 {
		t.Fatalf("merged %d; files %d and %d", merged, len(parquetFiles(t, dir, "records", d0)), len(parquetFiles(t, dir, "records", d1)))
	}
	afterAgg, afterN := snapshot(t, s)
	if afterN != beforeN || afterN != 1250 || len(afterAgg) != len(beforeAgg) {
		t.Fatalf("after compaction %d rows (before %d), %d groups (before %d)", afterN, beforeN, len(afterAgg), len(beforeAgg))
	}
	// Equal up to the order of floating-point summation.
	for i := range afterAgg {
		a, b := afterAgg[i], beforeAgg[i]
		if a.Count != b.Count || !reflect.DeepEqual(a.Group, b.Group) || !a.Bucket.Equal(*b.Bucket) || !close(a.Mean, b.Mean) || !close(a.Variance, b.Variance) ||
			a.Min != b.Min || a.Max != b.Max || !close(a.Quantiles[0], b.Quantiles[0]) || !close(a.Quantiles[1], b.Quantiles[1]) {
			t.Fatalf("group %d differs:\n%+v\n%+v", i, a, b)
		}
	}
	// Nothing left to merge; the merged file is not merged again.
	if merged, err := s.(Compactor).Compact(); err != nil || merged != 0 {
		t.Fatalf("second compaction merged %d: %v", merged, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "records", "day="+d0, compactMarker+"*")); len(m) != 0 {
		t.Fatalf("markers left: %v", m)
	}

	// A newer schema adds a column; old and new files merge by name.
	s.Close()
	s2 := open(t, "duckdb", dir, recordsV2)
	extra := fixture(CompactFiles*10, 10)
	for i := range extra {
		extra[i]["response_bytes"] = int64(i)
	}
	for i := 0; i < len(extra); i += 10 {
		if err := s2.Append("records", extra[i:i+10]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s2.(Compactor).Compact(); err != nil {
		t.Fatal(err)
	}
	n, withNew := 0, 0
	if err := s2.Scan("records", Filter{}, func(r Row) error {
		n++
		if _, ok := r["response_bytes"]; ok {
			withNew++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1250+len(extra) || withNew != len(extra) {
		t.Fatalf("%d rows, %d with the new column", n, withNew)
	}
}

// TestCompactRecoversFromCrash: after a crash between the merged file's
// rename and the removal of the files it replaced, opening the store
// removes them, so no row is counted twice; a merge that never reached its
// rename leaves the original files.
func TestCompactRecoversFromCrash(t *testing.T) {
	dir := t.TempDir()
	s := open(t, "duckdb", dir, recordsV1)
	rows := fixture(400, 11)[:CompactFiles*10] // all on day0
	for i := 0; i < len(rows); i += 10 {
		if err := s.Append("records", rows[i:i+10]); err != nil {
			t.Fatal(err)
		}
	}
	d0 := DayOf(day0)
	originals := parquetFiles(t, dir, "records", d0)
	pdir := filepath.Join(dir, "records", "day="+d0)
	// Simulate the crash: a copy of the data as the merged file, with its
	// marker, and the originals still present.
	ds := s.(*duckStore)
	lits := make([]string, len(originals))
	for i, p := range originals {
		lits[i] = sqlString(p)
	}
	merged := filepath.Join(pdir, "part-9999999999999999999-999999.parquet")
	if _, err := ds.w.Exec("COPY (SELECT * FROM read_parquet([" + strings.Join(lits, ",") + "], union_by_name=true)) TO " + sqlString(merged) + " (FORMAT parquet)"); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(filepath.Join(pdir, compactMarker+filepath.Base(merged)), []byte(strings.Join(originals, "\n")+"\n")); err != nil {
		t.Fatal(err)
	}
	// And an abandoned merge of another compaction that never renamed.
	if err := os.WriteFile(filepath.Join(pdir, "part-1.parquet.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(filepath.Join(pdir, compactMarker+"part-1.parquet"), []byte(originals[0]+"\n")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2 := open(t, "duckdb", dir, recordsV1)
	if got := parquetFiles(t, dir, "records", d0); len(got) != 1 || got[0] != merged {
		t.Fatalf("files after recovery: %v", got)
	}
	if left, _ := filepath.Glob(filepath.Join(pdir, ".compact-*")); len(left) != 0 {
		t.Fatalf("markers left: %v", left)
	}
	if _, n := snapshot(t, s2); n != len(rows) {
		t.Fatalf("%d rows after recovery, want %d", n, len(rows))
	}
}
