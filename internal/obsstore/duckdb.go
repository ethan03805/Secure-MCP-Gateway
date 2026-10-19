//go:build cgo

package obsstore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/duckdb/duckdb-go/v2" // official DuckDB driver (cgo)
)

const duckdbAvailable = true

// duckStore writes one zstd-compressed Parquet file per flushed batch and
// day partition and answers queries with DuckDB over those files. DuckDB
// runs in memory; the Parquet files are the store. Extensions are never
// installed or loaded from the network (FR-12.2): JSON and Parquet support
// are built into the driver's library.
//
// Batches are written by a second in-memory DuckDB instance with a single
// thread (w), which runs each COPY entirely on the calling thread: the
// store writer's thread, at lowered priority (internal/analytics). Through
// the two-threaded query instance (db) a batch's COPY ran on two threads
// that, on a host whose processors are all busy, waited for each other:
// each batch took about twice its idle CPU time, five batches a second per
// table (FR-9.5), most of observation's CPU time on the 4-CPU CI runners
// and part of what put it over its FR-11.4 budget.
type duckStore struct {
	*base
	db      *sql.DB // queries and research exports
	w       *sql.DB // store batches (Append)
	c       *sql.DB // compaction (Compact)
	staging string
	// rw keeps compaction from removing files a query is reading: Scan
	// and Aggregate hold it shared from listing the files to the last row,
	// Compact exclusively while it swaps merged files in.
	rw sync.RWMutex
}

// writerMemory is the memory limit of the single-threaded instance that
// writes batches (at most 1,000 rows each, FR-9.5); it comes out of
// Options.MemoryLimit, as does the compaction instance's, so the three
// instances together keep CP-33's bound.
const writerMemory = 64 << 20

func openDuckDB(o Options) (Store, error) {
	const opts = "autoinstall_known_extensions=false&autoload_known_extensions=false"
	queryMem, writeMem := o.MemoryLimit, int64(writerMemory)
	if o.MemoryLimit > 0 {
		writeMem = min(writeMem, o.MemoryLimit/4)
		queryMem = o.MemoryLimit - 2*writeMem // the compaction instance has as much as the writer
	}
	open := func(threads int, mem int64, extra string) (*sql.DB, error) {
		dsn := "?threads=" + strconv.Itoa(threads) + "&" + opts + extra
		if mem > 0 {
			dsn += "&memory_limit=" + strconv.FormatInt(mem>>20, 10) + "MB"
		}
		db, err := sql.Open("duckdb", dsn)
		if err != nil {
			return nil, fmt.Errorf("duckdb: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("duckdb: %w", err)
		}
		return db, nil
	}
	db, err := open(2, queryMem, "")
	if err != nil {
		return nil, err
	}
	w, err := open(1, writeMem, "")
	if err != nil {
		db.Close()
		return nil, err
	}
	// Compaction merges files in a third single-threaded instance: in the
	// writer's, a merge held up the batches behind it and the queue filled
	// (FR-11.6). Row order within a merged file does not matter (queries
	// order by ts), so DuckDB need not buffer to keep it.
	c, err := open(1, writeMem, "&preserve_insertion_order=false")
	if err != nil {
		db.Close()
		w.Close()
		return nil, err
	}
	s := &duckStore{base: newBase(o), db: db, w: w, c: c, staging: filepath.Join(o.Dir, ".staging")}
	if err := os.MkdirAll(s.staging, 0o700); err != nil {
		s.Close()
		return nil, err
	}
	// Leftover staging files from a crash are partial batches that were
	// never published; remove them.
	if m, _ := filepath.Glob(filepath.Join(s.staging, "*")); len(m) > 0 {
		for _, p := range m {
			os.Remove(p)
		}
	}
	if err := s.finishCompactions(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *duckStore) Backend() string { return "duckdb" }

func sqlString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func quoteIdent(s string) string { return `"` + s + `"` }

func columnsSpec(cols []Column) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, sqlString(c.Name)+":"+sqlString(c.Type))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// WriteParquet implements ParquetWriter.
func (s *duckStore) WriteParquet(cols []Column, jsonlPath, parquetPath string) error {
	return writeParquet(s.db, cols, jsonlPath, parquetPath)
}

// writeParquet copies a JSON Lines file with the columns cols to a
// zstd-compressed Parquet file with db.
func writeParquet(db *sql.DB, cols []Column, jsonlPath, parquetPath string) error {
	for _, c := range cols {
		if !validName(c.Name) {
			return fmt.Errorf("%w: %q", ErrBadColumn, c.Name)
		}
	}
	sel := make([]string, 0, len(cols))
	for _, c := range cols {
		sel = append(sel, quoteIdent(c.Name))
	}
	// Identifiers are validated column names; paths are quoted literals.
	q := fmt.Sprintf("COPY (SELECT %s FROM read_json(%s, format='newline_delimited', columns=%s)) TO %s (FORMAT parquet, COMPRESSION zstd)", //nolint:gosec // G201: validated identifiers and quoted literals only
		strings.Join(sel, ","), sqlString(jsonlPath), columnsSpec(cols), sqlString(parquetPath))
	if _, err := db.Exec(q); err != nil {
		return fmt.Errorf("duckdb: write parquet: %w", err)
	}
	return os.Chmod(parquetPath, 0o600)
}

func (s *duckStore) Append(table string, rows []Row) error {
	t, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownTable, table)
	}
	norm := make([]Row, 0, len(rows))
	for _, r := range rows {
		n, err := s.normalize(t, r)
		if err != nil {
			return err
		}
		norm = append(norm, n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for day, rs := range byDay(norm) {
		dir := s.partDir(table, day)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		name := s.nextName()
		tmp := filepath.Join(s.staging, name+".jsonl")
		// The staging file is read once by the COPY below and removed
		// (and removed at open after a crash), so it is not synced: an
		// fsync per batch and table only competed with the journal's
		// commits for the disk.
		if err := writeJSONL(tmp, t, rs, false); err != nil {
			return err
		}
		// Write under a temporary name and rename, so that a reader never
		// sees a partial Parquet file.
		part := filepath.Join(dir, name+".parquet")
		err := writeParquet(s.w, t.Columns, tmp, part+".tmp")
		os.Remove(tmp)
		if err != nil {
			os.Remove(part + ".tmp")
			return err
		}
		if err := os.Rename(part+".tmp", part); err != nil {
			return err
		}
	}
	s.countRows(table, len(norm))
	return nil
}

// source returns the read_parquet expression over the files in range and
// the set of columns present in them; ok is false when there are no files.
func (s *duckStore) source(table string, f Filter) (string, map[string]bool, bool, error) {
	files, err := s.files(table, ".parquet", f)
	if err != nil || len(files) == 0 {
		return "", nil, false, err
	}
	lits := make([]string, len(files))
	for i, p := range files {
		lits[i] = sqlString(p)
	}
	src := "read_parquet([" + strings.Join(lits, ",") + "], union_by_name=true)"
	rows, err := s.db.Query("DESCRIBE SELECT * FROM " + src) //nolint:gosec // G202: src holds quoted file-path literals only
	if err != nil {
		return "", nil, false, fmt.Errorf("duckdb: %w", err)
	}
	defer rows.Close()
	present := map[string]bool{}
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return "", nil, false, err
		}
		if name, ok := vals[0].(string); ok {
			present[name] = true
		}
	}
	return src, present, true, rows.Err()
}

// where renders the filter as SQL with parameters. A column absent from
// every file reads as NULL, which matches only the empty string.
func where(f Filter, present map[string]bool) (string, []any, bool) {
	var conds []string
	var args []any
	if !f.From.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, f.From.UTC())
	}
	if !f.To.IsZero() {
		conds = append(conds, "ts < ?")
		args = append(args, f.To.UTC())
	}
	cols := make([]string, 0, len(f.Equals))
	for c := range f.Equals {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	for _, c := range cols {
		vals := f.Equals[c]
		if !present[c] {
			matchEmpty := false
			for _, v := range vals {
				if v == "" {
					matchEmpty = true
				}
			}
			if !matchEmpty {
				return "", nil, false
			}
			continue
		}
		if len(vals) == 0 {
			return "", nil, false
		}
		ph := strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",")
		conds = append(conds, fmt.Sprintf("coalesce(CAST(%s AS VARCHAR), '') IN (%s)", quoteIdent(c), ph))
		for _, v := range vals {
			args = append(args, v)
		}
	}
	if len(conds) == 0 {
		return "", args, true
	}
	return " WHERE " + strings.Join(conds, " AND "), args, true
}

func (s *duckStore) Scan(table string, f Filter, fn func(Row) error) error {
	t, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownTable, table)
	}
	for c := range f.Equals {
		if !validName(c) {
			return fmt.Errorf("%w: %q", ErrBadColumn, c)
		}
	}
	s.rw.RLock()
	defer s.rw.RUnlock()
	src, present, ok, err := s.source(table, f)
	if err != nil || !ok {
		return err
	}
	w, args, ok := where(f, present)
	if !ok {
		return nil
	}
	q := "SELECT * FROM " + src + w + " ORDER BY ts" //nolint:gosec // G202: quoted paths, validated identifiers, values as parameters
	if f.Limit > 0 {
		q += " LIMIT " + strconv.Itoa(f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return fmt.Errorf("duckdb: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		r := Row{}
		for i, c := range cols {
			if vals[i] == nil {
				continue
			}
			if col, ok := t.column(c); ok {
				v, err := convert(col, vals[i])
				if err != nil {
					return fmt.Errorf("%s: %w", c, err)
				}
				r[c] = v
			} else {
				r[c] = vals[i]
			}
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *duckStore) Aggregate(q AggQuery) ([]AggRow, error) {
	if _, err := validateAgg(s.tables, &q); err != nil {
		return nil, err
	}
	s.rw.RLock()
	defer s.rw.RUnlock()
	src, present, ok, err := s.source(q.Table, q.Filter)
	if err != nil || !ok || !present[q.Feature] {
		return []AggRow{}, err
	}
	w, args, ok := where(q.Filter, present)
	if !ok {
		return []AggRow{}, nil
	}
	if w == "" {
		w = " WHERE "
	} else {
		w += " AND "
	}
	w += quoteIdent(q.Feature) + " IS NOT NULL"

	var inner, groups, sel []string
	inner = append(inner, "CAST("+quoteIdent(q.Feature)+" AS DOUBLE) AS x", "ts")
	for i, g := range q.GroupBy {
		alias := "g" + strconv.Itoa(i)
		if present[g] {
			inner = append(inner, quoteIdent(g)+" AS "+alias)
		} else {
			inner = append(inner, "NULL AS "+alias)
		}
		groups = append(groups, alias)
	}
	sel = append(sel, groups...)
	if q.Bucket > 0 {
		b := strconv.FormatInt(q.Bucket.Microseconds(), 10)
		sel = append(sel, "(epoch_us(ts) // "+b+") * "+b+" AS bucket_us")
		groups = append(groups, "bucket_us")
	}
	sel = append(sel, "count(x)", "avg(x)", "coalesce(var_samp(x), 0)", "min(x)", "max(x)")
	for _, p := range q.Quantiles {
		sel = append(sel, "quantile_cont(x, "+strconv.FormatFloat(p, 'g', -1, 64)+")")
	}
	if len(q.Histogram) > 0 {
		hb := q.Histogram
		bound := func(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
		sel = append(sel, "count(*) FILTER (WHERE x <= "+bound(hb[0])+")")
		for i := 1; i < len(hb); i++ {
			sel = append(sel, "count(*) FILTER (WHERE x > "+bound(hb[i-1])+" AND x <= "+bound(hb[i])+")")
		}
		sel = append(sel, "count(*) FILTER (WHERE x > "+bound(hb[len(hb)-1])+")")
	}
	stmt := "SELECT " + strings.Join(sel, ", ") + " FROM (SELECT " + strings.Join(inner, ", ") + " FROM " + src + w + ") t" //nolint:gosec // G202: validated identifiers, numeric literals and quoted paths; values as parameters
	if len(groups) > 0 {
		stmt += " GROUP BY " + strings.Join(groups, ", ")
	}
	rows, err := s.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("duckdb: %w", err)
	}
	defer rows.Close()
	var out []AggRow
	for rows.Next() {
		n := len(q.GroupBy)
		vals := make([]any, len(sel))
		ptrs := make([]any, len(sel))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := AggRow{Group: map[string]string{}}
		for i, g := range q.GroupBy {
			r.Group[g] = groupString(vals[i])
		}
		i := n
		if q.Bucket > 0 {
			us, _ := vals[i].(int64)
			b := time.UnixMicro(us).UTC()
			r.Bucket = &b
			i++
		}
		r.Count, _ = vals[i].(int64)
		r.Mean, _ = toFloat(vals[i+1])
		r.Variance, _ = toFloat(vals[i+2])
		r.Min, _ = toFloat(vals[i+3])
		r.Max, _ = toFloat(vals[i+4])
		i += 5
		for range q.Quantiles {
			v, _ := toFloat(vals[i])
			r.Quantiles = append(r.Quantiles, v)
			i++
		}
		if len(q.Histogram) > 0 {
			r.Histogram = make([]int64, len(q.Histogram)+1)
			for k := range r.Histogram {
				r.Histogram[k], _ = vals[i].(int64)
				i++
			}
		}
		if r.Count < 2 {
			r.Variance = 0
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortAgg(out)
	return out, nil
}

func (s *duckStore) Retain(now time.Time, keep time.Duration) ([]string, error) {
	s.rw.Lock()
	defer s.rw.Unlock()
	return s.retain(now, keep)
}

// Compaction (Compactor): every batch is its own Parquet file, up to five
// a second per table and day (FR-9.5), and a query opens every file of its
// range, so that queries over 30 days slowed with the number of batches
// rather than the number of rows. Compact merges the small files of each
// partition into one.
const (
	// CompactFiles is the number of small files a partition must hold
	// before Compact merges them.
	CompactFiles = 16
	// compactSmall is the size below which a file is merged; larger files
	// (earlier merges) are left alone, so a partition is not rewritten
	// whole at every compaction.
	compactSmall = 32 << 20
	// compactRowGroup bounds the rows the single-threaded writer instance
	// buffers per row group, within its memory limit (writerMemory, as the writer).
	compactRowGroup = 16384
)

// Compact merges, in every table and day partition, the files smaller than
// compactSmall into one file when there are at least CompactFiles of them.
// The merged file is written beside them under a temporary name; it
// replaces them while no query is reading (rw) and no batch or retention
// is changing the partition (mu). It returns the number of files merged.
func (s *duckStore) Compact() (int, error) {
	merged := 0
	for name := range s.tables {
		days, err := s.days(name, Filter{})
		if err != nil {
			return merged, err
		}
		for _, d := range days {
			t0 := time.Now()
			n, err := s.compactPartition(name, d)
			merged += n
			if err != nil {
				return merged, err
			}
			// Pause as long as the merge took: batches written while a
			// merge ran took longer, and at 2,000 records per second a run
			// of merges without pauses filled the writer's queue (FR-11.6).
			if n > 0 {
				time.Sleep(time.Since(t0))
			}
		}
	}
	return merged, nil
}

func (s *duckStore) compactPartition(table, day string) (int, error) {
	dir := s.partDir(table, day)
	all, err := filepath.Glob(filepath.Join(dir, "*.parquet"))
	if err != nil {
		return 0, err
	}
	var small []string
	for _, p := range all {
		if fi, err := os.Stat(p); err == nil && fi.Size() < compactSmall {
			small = append(small, p)
		}
	}
	if len(small) < CompactFiles {
		return 0, nil
	}
	sort.Strings(small)
	lits := make([]string, len(small))
	for i, p := range small {
		lits[i] = sqlString(p)
	}
	part := filepath.Join(dir, s.nextName()+".parquet")
	q := fmt.Sprintf("COPY (SELECT * FROM read_parquet([%s], union_by_name=true)) TO %s (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE %d)", //nolint:gosec // G201: quoted path literals and a numeric constant only
		strings.Join(lits, ","), sqlString(part+".tmp"), compactRowGroup)
	if _, err := s.c.Exec(q); err != nil {
		os.Remove(part + ".tmp")
		return 0, fmt.Errorf("duckdb: compact %s/day=%s: %w", table, day, err)
	}
	if err := os.Chmod(part+".tmp", 0o600); err != nil {
		os.Remove(part + ".tmp")
		return 0, err
	}
	s.rw.Lock()
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.rw.Unlock()
	// Retention may have removed the partition while the merge ran.
	if _, err := os.Stat(dir); err != nil {
		os.Remove(part + ".tmp")
		return 0, nil
	}
	// The marker lists the merged files; after a crash between the rename
	// and their removal, open removes them (finishCompactions), so no row
	// is counted twice.
	marker := filepath.Join(dir, compactMarker+filepath.Base(part))
	if err := writeSynced(marker, []byte(strings.Join(small, "\n")+"\n")); err != nil {
		os.Remove(part + ".tmp")
		return 0, err
	}
	if err := os.Rename(part+".tmp", part); err != nil {
		os.Remove(part + ".tmp")
		os.Remove(marker)
		return 0, err
	}
	for _, p := range small {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return len(small), err
		}
	}
	return len(small), os.Remove(marker)
}

// compactMarker starts the name of a compaction's marker file.
const compactMarker = ".compact-"

func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// finishCompactions completes or abandons the compactions a crash
// interrupted: when the merged file exists, the files it replaced are
// removed; otherwise they stay and the partial merge is removed.
func (s *duckStore) finishCompactions() error {
	for name := range s.tables {
		days, err := s.days(name, Filter{})
		if err != nil {
			return err
		}
		for _, d := range days {
			dir := s.partDir(name, d)
			markers, _ := filepath.Glob(filepath.Join(dir, compactMarker+"*"))
			for _, m := range markers {
				part := filepath.Join(dir, strings.TrimPrefix(filepath.Base(m), compactMarker))
				if _, err := os.Stat(part); err == nil {
					b, err := os.ReadFile(m)
					if err != nil {
						return err
					}
					for _, p := range strings.Fields(string(b)) {
						if filepath.Dir(p) == dir {
							os.Remove(p)
						}
					}
				}
				os.Remove(part + ".tmp")
				os.Remove(m)
			}
			tmps, _ := filepath.Glob(filepath.Join(dir, "*.parquet.tmp"))
			for _, p := range tmps {
				os.Remove(p)
			}
		}
	}
	return nil
}

func (s *duckStore) Stats() (Stats, error) { return s.stats("duckdb") }

func (s *duckStore) Close() error {
	werr := errors.Join(s.w.Close(), s.c.Close())
	if err := s.db.Close(); err != nil {
		return err
	}
	return werr
}
