// Command reqreport maps `go test -json` output to SRS requirement IDs
// (FR-12.10) and produces the status document the project website reads.
//
// Tests claim requirements through internal/reqtest: reqtest.Verifies logs
// "VERIFIES: <ids>" (a full claim) and reqtest.Partial logs "PARTIAL: <ids>"
// (a partial claim). reqreport reads every requirement ID and its element
// allocation from srs_build/req*.txt and computes, per requirement:
//
//   - failing: a claiming test failed (or never finished)
//   - verified: at least one passing full claim and no failing claim
//   - partial: only partial claims passed
//   - unverified: no passing claim (skipped tests do not verify)
//
// Usage:
//
//	go test -json -coverpkg=./... -coverprofile=build/cover.out ./... > build/go-test.json
//	go run ./tools/reqreport -in build/go-test.json -coverprofile build/cover.out
//	go run ./tools/reqreport history -status build/status.json -history site-data/history.json
//
// It writes <out>.json, <out>.md and, unless -status is empty, the status
// document (schema 1). The exit status is 1 when any requirement is failing.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "history" {
		flags := flag.NewFlagSet("history", flag.ExitOnError)
		status := flags.String("status", "build/status.json", "status document to summarize")
		history := flags.String("history", "history.json", "history file to update in place")
		_ = flags.Parse(os.Args[2:])
		if err := runHistory(*status, *history); err != nil {
			fmt.Fprintln(os.Stderr, "reqreport:", err)
			os.Exit(2)
		}
		return
	}
	code, err := run(os.Args[1:], os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reqreport:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

type options struct {
	in, out, status, srs, arch, elements, coverprofile, agents, hostile, gomod string
	commit, conclusion                                                         string
	failOnFailing                                                              bool
}

func run(args []string, stdin io.Reader, stdout io.Writer) (int, error) {
	var o options
	flags := flag.NewFlagSet("reqreport", flag.ContinueOnError)
	flags.StringVar(&o.in, "in", "-", "go test -json output (- for standard input)")
	flags.StringVar(&o.out, "out", "build/reqreport", "report path without extension")
	flags.StringVar(&o.status, "status", "build/status.json", "status document path (empty to skip)")
	flags.StringVar(&o.srs, "srs", "srs_build", "directory with req*.txt")
	flags.StringVar(&o.arch, "arch", "ArchitectureV2.md", "architecture document with element headings")
	flags.StringVar(&o.elements, "elements", "docs/status/elements.json", "element implementation status (optional)")
	flags.StringVar(&o.coverprofile, "coverprofile", "", "Go coverprofile (optional)")
	flags.StringVar(&o.agents, "agents", "build/agents.json", "harness compatibility results (optional)")
	flags.StringVar(&o.hostile, "hostile", "build/hostile.json", "hostile fixture results (optional)")
	flags.StringVar(&o.gomod, "gomod", "go.mod", "go.mod, for the module path")
	flags.StringVar(&o.commit, "commit", os.Getenv("GITHUB_SHA"), "commit SHA (default $GITHUB_SHA or git HEAD)")
	flags.StringVar(&o.conclusion, "conclusion", "", "CI conclusion (default success or failure from the results)")
	flags.BoolVar(&o.failOnFailing, "fail-on-failing", true, "exit 1 when any requirement is failing")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}

	r := stdin
	if o.in != "-" {
		f, err := os.Open(o.in)
		if err != nil {
			return 2, err
		}
		defer f.Close()
		r = f
	}
	log, err := parseTestLog(r)
	if err != nil {
		return 2, err
	}
	reqs, err := loadRequirements(o.srs)
	if err != nil {
		return 2, err
	}
	els, err := loadElements(o.arch)
	if err != nil {
		return 2, err
	}
	if els, err = mergeElementStatus(els, o.elements); err != nil {
		return 2, err
	}
	module := modulePath(o.gomod)
	var cov *Coverage
	if o.coverprofile != "" {
		if cov, err = loadCoverage(o.coverprofile, module); err != nil {
			return 2, err
		}
	}
	agents, err := optionalArray(o.agents)
	if err != nil {
		return 2, err
	}
	hostile, err := optionalArray(o.hostile)
	if err != nil {
		return 2, err
	}

	results := buildResults(reqs, log, module)
	for _, t := range log.Tests {
		t.Package = shortPackage(t.Package, module)
	}
	for _, p := range log.Packages {
		p.Name = shortPackage(p.Name, module)
	}
	commit := o.commit
	if commit == "" {
		if b, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
			commit = strings.TrimSpace(string(b))
		}
	}
	meta := Meta{
		Commit:    commit,
		Repo:      os.Getenv("GITHUB_REPOSITORY"),
		ServerURL: os.Getenv("GITHUB_SERVER_URL"),
		RunID:     os.Getenv("GITHUB_RUN_ID"),
		Workflow:  os.Getenv("GITHUB_WORKFLOW"),
		Now:       time.Now(),
	}
	if meta.Repo == "" {
		meta.Repo = "ethan03805/Secure-MCP-Gateway"
	}
	if meta.Workflow == "" {
		meta.Workflow = "local"
	}
	st := buildStatus(meta, log, cov, results, els, agents, hostile)
	st.CI.Conclusion = o.conclusion
	if st.CI.Conclusion == "" {
		st.CI.Conclusion = "success"
		if st.Tests.Failed > 0 || st.Requirements.Failing > 0 {
			st.CI.Conclusion = "failure"
		}
	}

	report := struct {
		GeneratedAt  string       `json:"generatedAt"`
		Commit       string       `json:"commit"`
		Summary      ReqSummary   `json:"summary"`
		Requirements []*ReqResult `json:"requirements"`
	}{st.GeneratedAt, st.Commit, st.Requirements, results}
	report.Summary.Items = nil
	report.Summary.ByElement = st.Requirements.ByElement
	if err := writeJSON(o.out+".json", report); err != nil {
		return 2, err
	}
	if err := os.WriteFile(o.out+".md", []byte(renderMarkdown(st, results)), 0o644); err != nil {
		return 2, err
	}
	written := []string{o.out + ".json", o.out + ".md"}
	if o.status != "" {
		if err := writeJSON(o.status, st); err != nil {
			return 2, err
		}
		written = append(written, o.status)
	}
	rs := st.Requirements
	fmt.Fprintf(stdout, "reqreport: %d requirements: %d verified, %d partial, %d failing, %d unverified; tests %d passed, %d failed, %d skipped; wrote %s\n",
		rs.Total, rs.Verified, rs.Partial, rs.Failing, rs.Unverified, st.Tests.Passed, st.Tests.Failed, st.Tests.Skipped, strings.Join(written, ", "))
	for _, res := range results {
		if !res.InSRS {
			fmt.Fprintf(stdout, "reqreport: warning: %s is claimed by tests but is not an SRS requirement\n", res.ID)
		}
	}
	if o.failOnFailing && rs.Failing > 0 {
		return 1, nil
	}
	return 0, nil
}

// optionalArray reads a JSON array from path; a missing file yields an empty
// array.
func optionalArray(path string) ([]any, error) {
	if path == "" {
		return []any{}, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var v []any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if v == nil {
		v = []any{}
	}
	return v, nil
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
