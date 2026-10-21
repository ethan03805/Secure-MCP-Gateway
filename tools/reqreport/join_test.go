package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestJoinClaimsOnlyWhenEveryPlatformPassed: the joined test claims the
// requirement in full only when every named test passed in its events
// file; a failed one fails it, and a missing file, a missing test or a
// skipped one makes it skip without a claim (FR-12.10).
func TestJoinClaimsOnlyWhenEveryPlatformPassed(t *testing.T) {
	reqtest.Partial(t, "FR-12.10")
	dir := t.TempDir()
	write := func(name, test, action string) string {
		p := filepath.Join(dir, name)
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		for _, e := range []event{{Action: "run", Package: "p", Test: test}, {Action: "output", Package: "p", Test: test, Output: "PARTIAL: FR-20.8\n"}, {Action: action, Package: "p", Test: test}} {
			if err := enc.Encode(e); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mac := write("mac.json", "a::setup", "pass")
	win := write("win.json", "a::setup", "pass")
	bad := write("bad.json", "a::setup", "fail")
	skipped := write("skip.json", "a::setup", "skip")
	run := func(needs ...string) *TestRun {
		t.Helper()
		out := filepath.Join(t.TempDir(), "join.json")
		args := []string{"-test", "j::fr_20_8", "-full", "FR-20.8", "-out", out}
		for _, n := range needs {
			args = append(args, "-need", n)
		}
		if code, err := runJoin(args, &bytes.Buffer{}); err != nil || code != 0 {
			t.Fatalf("join: %d %v", code, err)
		}
		f, err := os.Open(out)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		log, err := parseTestLog(f)
		if err != nil || len(log.Tests) != 1 {
			t.Fatalf("%v %d tests", err, len(log.Tests))
		}
		return log.Tests[0]
	}
	if tr := run(mac+"#a::setup", win+"#a::setup"); tr.Result != "pass" || len(tr.Claims) != 1 || tr.Claims[0].ID != "FR-20.8" || tr.Claims[0].Partial {
		t.Errorf("all passed: %s %+v", tr.Result, tr.Claims)
	}
	if tr := run(mac+"#a::setup", bad+"#a::setup"); tr.Result != "fail" || len(tr.Claims) != 1 {
		t.Errorf("one failed: %s %+v", tr.Result, tr.Claims)
	}
	for _, needs := range [][]string{
		{mac + "#a::setup", filepath.Join(dir, "none.json") + "#a::setup"},
		{mac + "#a::setup", win + "#a::other"},
		{mac + "#a::setup", skipped + "#a::setup"},
	} {
		if tr := run(needs...); tr.Result != "skip" || len(tr.Claims) != 0 {
			t.Errorf("%v: %s %+v", needs, tr.Result, tr.Claims)
		}
	}
	evs := joinEvents("j", "p", []string{"FR-20.8"}, "why", []string{"x#y"}, map[string]string{"x#y": "pass"}, time.Unix(0, 0))
	var b strings.Builder
	for _, e := range evs {
		b.WriteString(e.Output)
	}
	if !strings.Contains(b.String(), "x#y pass") || !strings.Contains(b.String(), "why") {
		t.Errorf("events do not name the joined tests:\n%s", b.String())
	}
}
