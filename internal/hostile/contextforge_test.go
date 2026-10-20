package hostile

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestContextForgeRowsMatchSRS keeps CFRows in step with the HFC table of
// srs_build/req8-contextforge.txt.
func TestContextForgeRowsMatchSRS(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "srs_build", "req8-contextforge.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "TEXT: | HFC-") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimPrefix(line, "TEXT: "), "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		i := slices.IndexFunc(CFRows, func(r Row) bool { return r.ID == cells[0] })
		if i < 0 {
			t.Errorf("%s missing from CFRows", cells[0])
			continue
		}
		r := CFRows[i]
		if want := []string{r.ID, r.Attack, r.Behavior, r.Expected, r.Profiles}; !slices.Equal(cells, want) {
			t.Errorf("%s differs from the SRS:\n got  %q\n want %q", r.ID, want, cells)
		}
		got = append(got, cells[0])
	}
	if len(got) != 14 || len(CFRows) != 14 {
		t.Fatalf("SRS rows %v, CFRows %d", got, len(CFRows))
	}
}
