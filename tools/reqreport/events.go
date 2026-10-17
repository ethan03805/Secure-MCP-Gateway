package main

import (
	"bufio"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"
)

// Markers logged by internal/reqtest. VERIFIES is a full claim; PARTIAL is
// a claim that the test covers part of the requirement.
const (
	markerFull    = "VERIFIES:"
	markerPartial = "PARTIAL:"
	// markerScenario is an acceptance scenario claim (FR-19.4):
	// "SCENARIO: AT-01 AT-02 profile=standalone".
	markerScenario = "SCENARIO:"
)

type event struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"`
	Package string    `json:"Package"`
	Test    string    `json:"Test"`
	Output  string    `json:"Output"`
	Elapsed float64   `json:"Elapsed"`
}

// Claim is one requirement ID claimed by one test.
type Claim struct {
	ID      string
	Partial bool
}

// TestRun is the outcome of one test or subtest.
type TestRun struct {
	Package string
	Name    string // full test name including subtest path, e.g. TestA/case_1
	Result  string // pass, fail, skip, or "" when no terminal event arrived
	Claims  []Claim
	// Scenarios are the acceptance scenarios the test claims to execute.
	Scenarios []ScenarioClaim
}

// ScenarioClaim is one acceptance scenario claimed by one test in one
// profile.
type ScenarioClaim struct {
	ID      string
	Profile string
}

// Key identifies the test uniquely across packages.
func (t *TestRun) Key() string { return t.Package + "." + t.Name }

// PackageRun is the outcome of one package.
type PackageRun struct {
	Name    string
	Result  string // pass, fail, skip
	Passed  int
	Failed  int
	Skipped int
	Elapsed float64
}

// TestLog is everything reqreport needs from `go test -json`.
type TestLog struct {
	Tests    []*TestRun
	Packages []*PackageRun
	Start    time.Time
	End      time.Time
}

// parseTestLog reads `go test -json` output. Output lines are reassembled
// per test before marker parsing, because test2json splits long lines and
// interleaves output of parallel tests.
func parseTestLog(r io.Reader) (*TestLog, error) {
	tests := map[string]*TestRun{}
	pkgs := map[string]*PackageRun{}
	partial := map[string]string{} // test key -> unterminated output
	var order []string
	var pkgOrder []string
	log := &TestLog{}

	getTest := func(pkg, name string) *TestRun {
		k := pkg + "." + name
		t := tests[k]
		if t == nil {
			t = &TestRun{Package: pkg, Name: name}
			tests[k] = t
			order = append(order, k)
		}
		return t
	}
	getPkg := func(name string) *PackageRun {
		p := pkgs[name]
		if p == nil {
			p = &PackageRun{Name: name}
			pkgs[name] = p
			pkgOrder = append(pkgOrder, name)
		}
		return p
	}
	scanLine := func(t *TestRun, line string) {
		if i := strings.Index(line, markerScenario); i >= 0 {
			t.Scenarios = append(t.Scenarios, parseScenarioLine(line[i+len(markerScenario):])...)
		}
		for _, m := range []struct {
			marker  string
			partial bool
		}{{markerFull, false}, {markerPartial, true}} {
			i := strings.Index(line, m.marker)
			if i < 0 {
				continue
			}
			for _, id := range strings.Fields(line[i+len(m.marker):]) {
				if idPattern.MatchString(id) {
					t.Claims = append(t.Claims, Claim{ID: id, Partial: m.partial})
				}
			}
		}
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		var ev event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue // non-JSON lines, e.g. build errors printed by go test
		}
		if !ev.Time.IsZero() {
			if log.Start.IsZero() || ev.Time.Before(log.Start) {
				log.Start = ev.Time
			}
			if ev.Time.After(log.End) {
				log.End = ev.Time
			}
		}
		if ev.Package == "" {
			continue
		}
		if ev.Test == "" {
			switch ev.Action {
			case "pass", "fail", "skip":
				p := getPkg(ev.Package)
				p.Result = ev.Action
				p.Elapsed = ev.Elapsed
			}
			continue
		}
		t := getTest(ev.Package, ev.Test)
		k := t.Key()
		switch ev.Action {
		case "output":
			buf := partial[k] + ev.Output
			for {
				i := strings.IndexByte(buf, '\n')
				if i < 0 {
					break
				}
				scanLine(t, buf[:i])
				buf = buf[i+1:]
			}
			partial[k] = buf
		case "pass", "fail", "skip":
			if rest := partial[k]; rest != "" {
				scanLine(t, rest)
				delete(partial, k)
			}
			t.Result = ev.Action
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for k, rest := range partial {
		if rest != "" {
			scanLine(tests[k], rest)
		}
	}

	for _, k := range order {
		t := tests[k]
		log.Tests = append(log.Tests, t)
		p := getPkg(t.Package)
		switch t.Result {
		case "pass":
			p.Passed++
		case "fail", "":
			// A test with no terminal event was cut short by a panic or
			// timeout in its binary; count it as failed.
			p.Failed++
		case "skip":
			p.Skipped++
		}
	}
	for _, name := range pkgOrder {
		p := pkgs[name]
		if p.Result == "fail" && p.Failed == 0 {
			// Build failure, TestMain failure or a panic outside any test.
			p.Failed = 1
		}
		log.Packages = append(log.Packages, p)
	}
	sort.SliceStable(log.Packages, func(i, j int) bool { return log.Packages[i].Name < log.Packages[j].Name })
	return log, nil
}

// parseScenarioLine reads "AT-01 AT-02 profile=enforced". A line without a
// valid profile claims nothing.
func parseScenarioLine(rest string) []ScenarioClaim {
	var ids []string
	profile := ""
	for _, f := range strings.Fields(rest) {
		if p, ok := strings.CutPrefix(f, "profile="); ok {
			profile = p
		} else if scenarioPattern.MatchString(f) {
			ids = append(ids, f)
		}
	}
	if profile != profileStandalone && profile != profileEnforced {
		return nil
	}
	out := make([]ScenarioClaim, 0, len(ids))
	for _, id := range ids {
		out = append(out, ScenarioClaim{ID: id, Profile: profile})
	}
	return out
}
