package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestJobClaimsBecomeTestEvents: the installers workflow's job results
// become claiming tests (FR-12.10). A claim passes only when every job it
// names passed and its inspection checks hold, fails when one failed, and
// is skipped, with no claim, when one did not run; the macOS jobs are
// judged by their outcome output.
func TestJobClaimsBecomeTestEvents(t *testing.T) {
	reqtest.Partial(t, "FR-12.10")
	claims := []jobClaim{
		{Test: "t::all_pass", Jobs: []string{"a", "mac"}, Full: []string{"FR-20.17"}, Partial: []string{"FR-20.26"}, Why: "why"},
		{Test: "t::one_failed", Jobs: []string{"a", "b"}, Full: []string{"FR-20.18"}},
		{Test: "t::mac_unavailable", Jobs: []string{"a", "mac2"}, Full: []string{"FR-20.19"}},
		{Test: "t::not_in_needs", Jobs: []string{"missing"}, Full: []string{"FR-20.21"}},
		{Test: "t::check_fails", Jobs: []string{"a"}, Full: []string{"FR-20.22"},
			Contains: map[string][]string{"docs/install.md": {"smcpctl uninstall --purge"}}},
		{Test: "t::artifacts", Jobs: []string{"a"}, Full: []string{"SR-4.11-2"},
			NoArtifact: []string{"*.flatpak"}, Artifact: []string{"*.AppImage"}},
	}
	needs := map[string]needsJob{
		"a":    {Result: "success"},
		"b":    {Result: "failure"},
		"mac":  {Result: "success", Outputs: map[string]string{"outcome": "passed"}},
		"mac2": {Result: "success", Outputs: map[string]string{"outcome": "unavailable"}},
	}
	repo := fstest.MapFS{"docs/install.md": {Data: []byte("remove with smcpctl uninstall")}}
	evs := jobEvents(claims, needs, []string{"x.AppImage", "x.flatpak"}, repo, "desktop/installers", time.Unix(0, 0))
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	out := buf.String()
	log, err := parseTestLog(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*TestRun{}
	for _, tr := range log.Tests {
		got[tr.Name] = tr
	}
	want := map[string]struct {
		result string
		claims int
	}{
		"t::all_pass":        {"pass", 2},
		"t::one_failed":      {"fail", 1},
		"t::mac_unavailable": {"skip", 0},
		"t::not_in_needs":    {"skip", 0},
		"t::check_fails":     {"fail", 1},
		"t::artifacts":       {"fail", 1},
	}
	for name, w := range want {
		tr := got[name]
		if tr == nil {
			t.Errorf("%s: no test", name)
			continue
		}
		if tr.Result != w.result || len(tr.Claims) != w.claims {
			t.Errorf("%s: result %s with %d claims, want %s with %d", name, tr.Result, len(tr.Claims), w.result, w.claims)
		}
	}
	if c := got["t::all_pass"].Claims; len(c) == 2 && (c[0].ID != "FR-20.17" || c[0].Partial || c[1].ID != "FR-20.26" || !c[1].Partial) {
		t.Errorf("all_pass claims %+v", c)
	}
	for _, s := range []string{`does not contain \"smcpctl uninstall --purge\"`, "the installers include x.flatpak"} {
		if !strings.Contains(out, s) {
			t.Errorf("events lack %q", s)
		}
	}
}

// TestInstallerClaimsNameRealJobs: every job a claim names is a job of
// installers.yml, the workflow's claims job needs it, every requirement ID
// is one, and the status job merges the claims file.
func TestInstallerClaimsNameRealJobs(t *testing.T) {
	reqtest.Partial(t, "FR-12.10")
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "installers.yml"))
	if err != nil {
		t.Fatal(err)
	}
	needsLine := regexp.MustCompile(`(?m)^  claims:\n(?:    .*\n)*?    needs: \[([^\]]*)\]`).FindSubmatch(wf)
	if needsLine == nil {
		t.Fatal("installers.yml has no claims job with a needs list")
	}
	needs := map[string]bool{}
	for _, n := range strings.Split(string(needsLine[1]), ",") {
		needs[strings.TrimSpace(n)] = true
	}
	for _, c := range installerClaims {
		for _, j := range c.Jobs {
			if !regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(j) + `:$`).Match(wf) {
				t.Errorf("%s: no job %s in installers.yml", c.Test, j)
			}
			if !needs[j] {
				t.Errorf("%s: the claims job does not need %s", c.Test, j)
			}
		}
		for _, id := range append(append([]string{}, c.Full...), c.Partial...) {
			if !idPattern.MatchString(id) {
				t.Errorf("%s: %q is not a requirement ID", c.Test, id)
			}
		}
	}
	ci, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ci), "build/desktop-installers-test.json") {
		t.Error("the status job of ci.yml does not merge build/desktop-installers-test.json")
	}
}
