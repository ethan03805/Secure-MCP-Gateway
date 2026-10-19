package contextforge

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func hashed(stem, backend string) string {
	s := sha256.Sum256([]byte(backend))
	if len(stem) > 38 {
		stem = stem[:38]
	}
	return stem + "_" + hex.EncodeToString(s[:])[:8]
}

// FR-22.10 (part): the deterministic name mapping. Not covered here: the
// probe that supplies the names, writing them into a manifest_version 2
// manifest and the Tool Dispatcher sending the backend name.
func TestMapToolNames(t *testing.T) {
	reqtest.Partial(t, "FR-22.10")
	slug := GatewayName("deepwiki")
	if slug != "smcp-deepwiki" {
		t.Fatalf("gateway name %q", slug)
	}
	long := strings.Repeat("x", 60)
	backend := []string{
		slug + "-get-time",
		slug + "-get_time",
		slug + "-" + long,
		slug + "-read.file",
		slug + "-ask_question",
	}
	got, err := MapToolNames(slug, backend)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		slug + "-get-time":     hashed("get_time", slug+"-get-time"),
		slug + "-get_time":     hashed("get_time", slug+"-get_time"),
		slug + "-" + long:      hashed(long, slug+"-"+long),
		slug + "-read.file":    "read_file",
		slug + "-ask_question": "ask_question",
	}
	if len(got) != len(want) {
		t.Fatalf("%d names, want %d", len(got), len(want))
	}
	for _, n := range got {
		if want[n.BackendName] != n.Name {
			t.Errorf("%s -> %s, want %s", n.BackendName, n.Name, want[n.BackendName])
		}
		if !manifestToolName.MatchString(n.Name) {
			t.Errorf("%s is not a manifest name", n.Name)
		}
	}
	// The same tools in reverse order map to the same names.
	rev := slices.Clone(backend)
	slices.Reverse(rev)
	again, err := MapToolNames(slug, rev)
	if err != nil || !slices.Equal(got, again) {
		t.Fatalf("order changed the mapping:\n%v\n%v (%v)", got, again, err)
	}
	// A long slug does not change the manifest names.
	other, err := MapToolNames("smcp-"+strings.Repeat("s", 40), []string{"smcp-" + strings.Repeat("s", 40) + "-read.file"})
	if err != nil || other[0].Name != "read_file" {
		t.Fatalf("long slug: %v %v", other, err)
	}
}

func TestMapToolNamesRefusals(t *testing.T) {
	slug := "smcp-x"
	// Find two backend names whose mapped stems are equal and whose hashed
	// forms still collide is infeasible; a collision that survives is
	// built from a hashed form equal to another tool's plain name.
	a := slug + "-a-b"
	b := slug + "-a_b"
	plain := hashed("a_b", a)
	cases := map[string][]string{
		"served twice":    {slug + "-t", slug + "-t"},
		"empty":           {slug + "-"},
		"still colliding": {a, b, slug + "-" + plain},
	}
	for name, names := range cases {
		_, err := MapToolNames(slug, names)
		if packaging.ReasonOf(err) != ReasonToolNameCollision {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if name == "still colliding" && (!strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), slug+"-"+plain)) {
			t.Errorf("collision does not name both tools: %v", err)
		}
	}
}

func TestGatewayNameBounded(t *testing.T) {
	n := GatewayName(strings.Repeat("A.b", 40))
	if len(n) > 63 || strings.HasSuffix(n, "-") || !strings.HasPrefix(n, "smcp-") {
		t.Fatalf("gateway name %q", n)
	}
}
