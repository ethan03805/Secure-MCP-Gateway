package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWorkflowResultsClaimRequirements covers the results of the separate
// verification workflows (site-data/workflows.json): a successful run on a
// release tag is a full claim, on any other ref a partial claim, a failed
// run a failing claim; only the latest entry of each workflow counts, and
// cancelled runs, malformed entries and unknown IDs claim nothing.
func TestWorkflowResultsClaimRequirements(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	sha := recordSHA
	wfs := []WorkflowResult{
		{Workflow: "tap", Requirements: []string{"FR-1"}, Ref: "v1.0.0-rc.1", Commit: sha, Conclusion: "failure", Date: "2026-10-16T10:00:00Z"},
		{Workflow: "tap", Requirements: []string{"FR-1"}, Ref: "v1.0.0-rc.2", Commit: sha, Conclusion: "success", Date: "2026-10-17T10:00:00Z", RunURL: "https://example.com/run/1"},
		{Workflow: "reference-packages", Requirements: []string{"FR-2"}, Ref: "main", Commit: sha, Conclusion: "success", Date: "2026-10-17T10:00:00Z"},
		{Workflow: "broken", Requirements: []string{"FR-3"}, Ref: "v1.0.0", Commit: sha, Conclusion: "failure", Date: "2026-10-17T10:00:00Z"},
		{Workflow: "cancelled", Requirements: []string{"FR-4"}, Ref: "v1.0.0", Commit: sha, Conclusion: "cancelled", Date: "2026-10-17T10:00:00Z"},
		{Workflow: "short", Requirements: []string{"FR-4"}, Ref: "v1.0.0", Commit: "abc123", Conclusion: "success", Date: "2026-10-17T10:00:00Z"},
		{Workflow: "unknown", Requirements: []string{"FR-99"}, Ref: "v1.0.0", Commit: sha, Conclusion: "success", Date: "2026-10-17T10:00:00Z"},
	}
	reqs := []Requirement{{ID: "FR-1", Method: "Test"}, {ID: "FR-2", Method: "Test"}, {ID: "FR-3", Method: "Test"}, {ID: "FR-4", Method: "Test"}}
	results := buildResults(reqs, &TestLog{}, "example.com/m")
	warnings := applyWorkflowResults(results, wfs)
	want := map[string]string{"FR-1": StatusVerified, "FR-2": StatusPartial, "FR-3": StatusFailing, "FR-4": StatusUnverified}
	for _, r := range results {
		if r.Status != want[r.ID] {
			t.Errorf("%s: %s, want %s (%+v)", r.ID, r.Status, want[r.ID], r.Claims)
		}
	}
	if c := results[0].Claims; len(c) != 1 || !strings.Contains(c[0].Test, "workflow tap at v1.0.0-rc.2") || !strings.Contains(c[0].Test, "https://example.com/run/1") {
		t.Errorf("FR-1 claims %+v", c)
	}
	if len(warnings) != 3 {
		t.Errorf("warnings %q, want cancelled, short SHA and unknown ID", warnings)
	}

	// A missing file is no results; the run reads the file given with -workflows.
	if w, err := loadWorkflowResults(filepath.Join(t.TempDir(), "none.json")); err != nil || w != nil {
		t.Fatalf("missing file: %v %v", w, err)
	}
	p := filepath.Join(t.TempDir(), "workflows.json")
	b, _ := json.Marshal(wfs[:2])
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadWorkflowResults(p)
	if err != nil || len(got) != 2 || got[1].Ref != "v1.0.0-rc.2" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWorkflowResults(p); err == nil {
		t.Fatal("malformed file accepted")
	}
}

// TestRecordsInSubdirectories covers the runbook execution records under
// docs/verification/runbooks/: records in subdirectories are read, and a
// README.md in a subdirectory is skipped.
func TestRecordsInSubdirectories(t *testing.T) {
	reqtest.Verifies(t, "FR-12.10")
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "docs", "runbooks", "stop.md"), "# stop\n")
	dir := filepath.Join(root, "docs", "verification")
	writeFile(t, filepath.Join(dir, "runbooks", "README.md"), record("FR-9", "Inspection", "pass", "2026-01-01", "- `docs/runbooks/stop.md:1`"))
	writeFile(t, filepath.Join(dir, "runbooks", "runbook-stop-2026-10-17.md"), record("FR-9", "Inspection", "pass", "2026-10-17", "- `docs/runbooks/stop.md:1`"))
	recs, err := loadRecords(dir, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].File != filepath.Join("runbooks", "runbook-stop-2026-10-17.md") || len(recs[0].Problems) != 0 {
		t.Fatalf("%+v", recs)
	}
	reqs := []Requirement{{ID: "FR-9", Method: "Inspection"}}
	results := buildResults(reqs, &TestLog{}, "example.com/m")
	if w := applyRecords(results, reqs, recs, "docs/verification"); len(w) != 0 || results[0].Status != StatusVerified {
		t.Fatalf("%s %q", results[0].Status, w)
	}
}
