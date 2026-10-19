package cachestats

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Each registered cache reports its hits, misses, hit ratio and entries;
// a cache with no lookup has no ratio.
func TestSnapshotReportsHitRatios(t *testing.T) {
	reqtest.Partial(t, "FR-8.16")
	n := 3
	a := Register("test_a", "cache A", func() int { return n })
	Register("test_b", "cache B", nil)
	if again := Register("test_a", "other", nil); again != a {
		t.Fatal("Register made a second counter for one name")
	}
	a.Hit()
	a.Hit()
	a.Hit()
	a.Miss()
	got := map[string]Stat{}
	for _, s := range Snapshot() {
		got[s.Name] = s
	}
	sa, sb := got["test_a"], got["test_b"]
	if sa.Hits != 3 || sa.Misses != 1 || sa.Ratio == nil || *sa.Ratio != 0.75 || sa.Entries == nil || *sa.Entries != 3 || sa.Description != "cache A" {
		t.Fatalf("test_a: %+v", sa)
	}
	if sb.Hits != 0 || sb.Misses != 0 || sb.Ratio != nil || sb.Entries != nil {
		t.Fatalf("test_b: %+v", sb)
	}
}
