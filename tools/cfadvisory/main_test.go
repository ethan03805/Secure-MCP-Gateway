package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lockFile(t *testing.T, version string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lock.json")
	if err := os.WriteFile(p, []byte(`{"contextforge":{"version":"`+version+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The advisories of 2026-10-20 (gh api, trimmed to the members the check
// reads): v1.0.11 has no unfixed high or critical advisory; v1.0.6 has.
func TestRecordedAdvisories(t *testing.T) {
	adv := filepath.Join("testdata", "advisories-2026-10-20.json")
	var out bytes.Buffer
	if code, err := run([]string{"-lock", "../../packaging/contextforge.lock.json", "-date", "2026-10-20", adv}, &out); code != 0 {
		t.Fatalf("pinned release: %d %v\n%s", code, err, out.String())
	}
	if !strings.Contains(out.String(), "ok GHSA-8pcq-mx48-hjvj critical: fixed in 1.0.7") {
		t.Fatalf("output:\n%s", out.String())
	}
	out.Reset()
	code, _ := run([]string{"-lock", lockFile(t, "v1.0.6"), "-date", "2026-10-20", adv}, &out)
	if code != 1 || !strings.Contains(out.String(), "UNFIXED GHSA-gv3m-3mvj-w6f2 critical") {
		t.Fatalf("v1.0.6: %d\n%s", code, out.String())
	}
	// Advisories published after the date do not count.
	out.Reset()
	if code, _ := run([]string{"-lock", lockFile(t, "v1.0.6"), "-date", "2026-06-01", adv}, &out); code != 0 {
		t.Fatalf("before any advisory: %d\n%s", code, out.String())
	}
}

func TestJudge(t *testing.T) {
	v, _ := parseVersion("v1.0.11")
	mk := func(rng, patched string) advisory {
		a := advisory{GHSA: "GHSA-x", Severity: "high"}
		a.Vulns = make([]struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Range   string `json:"vulnerable_version_range"`
			Patched string `json:"patched_versions"`
		}, 1)
		a.Vulns[0].Range, a.Vulns[0].Patched = rng, patched
		return a
	}
	cases := []struct {
		rng, patched string
		fixed        bool
	}{
		{"< 1.0.7", "1.0.7", true},
		{"\u2060<= 1.0.12", "", false},
		{">= 1.0.0, < 1.0.11", "", true},
		{"package mcp-contextforge-gateway < v1.0.12", "v1.0.12", false},
		{"v1.0.11", "", false},
		{"all of them", "", false},
		{"<= 1.0.10", "", true},
	}
	for _, c := range cases {
		if _, fixed := judge(mk(c.rng, c.patched), v); fixed != c.fixed {
			t.Errorf("%q %q: fixed %v", c.rng, c.patched, fixed)
		}
	}
}
