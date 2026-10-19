package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// plannedSource adds a planned root with two planned children (TARGET:
// lines, SRS Section 2.8) and one planned child of the current FR-1.
const plannedSource = `
@FR-20 | Desktop application
P: —
S: The Gateway release SHALL include a desktop application.
A: E-01; F-01
V: Analysis | Review the verification results of every FR-20 child requirement; confirm each has passed.
SRC: OWNER
R: Because.
TARGET: v1.3.0

@FR-20.1 | Tray icon
P: FR-20
S: The desktop application SHALL show a tray icon.
A: E-01; F-01
V: Test | Check.
SRC: OWNER
R: Because.
TARGET: v1.3.0

@FR-20.2 | Notifications
P: FR-20
S: The desktop application SHALL notify.
A: E-02; F-01
V: Test | Check.
SRC: OWNER
R: Because.
TARGET: v1.3.0

@FR-1.9 | Planned listener option
P: FR-1
S: The Gateway SHALL offer a planned listener option.
A: E-02; F-01
V: Test | Check.
SRC: OWNER
R: Because.
TARGET: v1.3.0
`

// TestPlannedRequirements: a record with a TARGET: line is loaded with its
// target release, reported as planned while unverified, and kept out of the
// totals, the per-element roll-up and the items of the current requirement
// set, so it neither counts as unverified nor makes the run fail. A planned
// requirement a test verifies is reported verified (still outside the
// totals); one with a failing claim is counted as failing.
func TestPlannedRequirements(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "srs", "req1.txt"), reqSource)
	writeFile(t, filepath.Join(dir, "srs", "req6.txt"), plannedSource)
	reqs, err := loadRequirements(filepath.Join(dir, "srs"))
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]string{}
	for _, r := range reqs {
		targets[r.ID] = r.Target
	}
	if targets["FR-20.1"] != "v1.3.0" || targets["FR-1.1"] != "" || len(reqs) != 7 {
		t.Fatalf("targets %v", targets)
	}

	arch := writeFile(t, filepath.Join(dir, "arch.md"), archSource)
	gomod := writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.26\n")
	const pkg = "example.com/m/internal/a"
	runWith := func(log string) (int, map[string]any, string) {
		t.Helper()
		in := writeFile(t, filepath.Join(dir, "go-test.json"), log)
		out := filepath.Join(dir, "build", "reqreport")
		statusPath := filepath.Join(dir, "build", "status.json")
		args := []string{"-in", in, "-out", out, "-status", statusPath, "-srs", filepath.Join(dir, "srs"), "-arch", arch,
			"-elements", "", "-gomod", gomod, "-commit", "deadbeef", "-agents", "", "-hostile", "", "-appendix", "", "-records", "", "-workflows", ""}
		var stdout bytes.Buffer
		code, err := run(args, nil, &stdout)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(statusPath)
		if err != nil {
			t.Fatal(err)
		}
		var st map[string]any
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatal(err)
		}
		md, _ := os.ReadFile(out + ".md")
		return code, st["requirements"].(map[string]any), string(md)
	}
	plannedStatus := func(rs map[string]any) map[string]string {
		got := map[string]string{}
		for _, it := range rs["plannedItems"].([]any) {
			m := it.(map[string]any)
			if m["target"] != "v1.3.0" {
				t.Errorf("planned item %v lacks its target", m)
			}
			got[m["id"].(string)] = m["status"].(string)
		}
		return got
	}

	// FR-1.1 and SR-1-1 verified; nothing claims the planned requirements.
	log := ev("output", pkg, "TestA", "VERIFIES: FR-1.1 SR-1-1\n") + ev("pass", pkg, "TestA", "") + ev("pass", pkg, "", "")
	code, rs, md := runWith(log)
	if code != 0 {
		t.Fatalf("exit %d: planned requirements must not fail the run", code)
	}
	if rs["total"] != float64(3) || rs["verified"] != float64(2) || rs["unverified"] != float64(1) || rs["failing"] != float64(0) || rs["planned"] != float64(4) {
		t.Fatalf("requirements %v", rs)
	}
	for _, it := range rs["items"].([]any) {
		if id := it.(map[string]any)["id"].(string); targets[id] != "" {
			t.Fatalf("planned %s in items", id)
		}
	}
	for _, roll := range rs["byElement"].([]any) {
		m := roll.(map[string]any)
		if m["element"] == "E-01" && m["total"] != float64(1) {
			t.Fatalf("planned requirements counted in the E-01 roll-up: %v", m)
		}
	}
	if got := plannedStatus(rs); got["FR-20"] != StatusPlanned || got["FR-20.1"] != StatusPlanned || got["FR-1.9"] != StatusPlanned {
		t.Fatalf("planned statuses %v", got)
	}
	unverified := md[strings.Index(md, "## Unverified requirements"):]
	if !strings.Contains(md, "## Planned for later releases") || strings.Contains(unverified[:strings.Index(unverified, "## Planned")], "FR-20") {
		t.Fatalf("markdown:\n%s", md)
	}

	// Both planned children verified: the planned parent's child analysis
	// verifies it. A failing claim on FR-1.9 is counted as failing.
	log = ev("output", pkg, "TestA", "VERIFIES: FR-1.1 FR-20.1 FR-20.2\n") + ev("pass", pkg, "TestA", "") +
		ev("output", pkg, "TestB", "VERIFIES: FR-1.9\n") + ev("fail", pkg, "TestB", "") + ev("fail", pkg, "", "")
	code, rs, _ = runWith(log)
	if code != 1 || rs["failing"] != float64(1) || rs["total"] != float64(3) {
		t.Fatalf("exit %d, requirements %v", code, rs)
	}
	if got := plannedStatus(rs); got["FR-20"] != StatusVerified || got["FR-20.1"] != StatusVerified || got["FR-1.9"] != StatusFailing {
		t.Fatalf("planned statuses %v", got)
	}
}

// TestChildAnalysisIgnoresPlannedChildren: a current parent verified by the
// review of its children is verified when its current children are, even
// while a planned child (SRS Section 2.8) is not.
func TestChildAnalysisIgnoresPlannedChildren(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	reqs := []Requirement{
		{ID: "FR-1", Method: "Analysis", Verify: childAnalysisPrefix + " child requirement; confirm each has passed."},
		{ID: "FR-1.1", Parent: "FR-1", Method: "Test"},
		{ID: "FR-1.9", Parent: "FR-1", Method: "Test", Target: "v1.3.0"},
	}
	results := []*ReqResult{
		{ID: "FR-1", InSRS: true, Status: StatusUnverified},
		{ID: "FR-1.1", InSRS: true, Status: StatusVerified, Claims: []ClaimRef{{Test: "t", Result: "pass"}}},
		{ID: "FR-1.9", InSRS: true, Status: StatusUnverified, Target: "v1.3.0"},
	}
	applyChildAnalysis(results, reqs)
	markPlanned(results)
	if results[0].Status != StatusVerified || results[2].Status != StatusPlanned {
		t.Fatalf("FR-1 %s, FR-1.9 %s", results[0].Status, results[2].Status)
	}
}
