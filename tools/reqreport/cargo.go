package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The cargo subcommand turns the result of the desktop application's Rust
// tests into `go test -json` events, so that their requirement claims are
// counted like the Go tests' and the console's (FR-12.10):
//
//	SMCP_CLAIMS_FILE=claims.tsv cargo test > cargo-test.txt
//	go run ./tools/reqreport cargo -test-output cargo-test.txt -claims claims.tsv \
//	    -package desktop/macos -out build/desktop-macos-test.json
//
// The Rust tests claim through desktop/src-tauri/src/claims.rs, which
// appends "<test path>\t<PARTIAL|VERIFIES>\t<ids>" to the claims file. The
// result of each test comes from cargo's "test <path> ... ok|FAILED|ignored"
// lines. A claiming test with no result line failed to finish and is
// reported as failing; a claim from an unnamed thread (a test run with
// --test-threads=1, whose thread has no test name) is refused.

var cargoResultLine = regexp.MustCompile(`^test (\S+) \.\.\. (ok|FAILED|ignored)\b`)

type cargoTest struct {
	result string // pass, fail, skip, or "" when no result line was seen
	claims []string
}

func runCargo(args []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet("cargo", flag.ContinueOnError)
	output := flags.String("test-output", "", "standard output of `cargo test`")
	claims := flags.String("claims", "", "claims file written by the tests (SMCP_CLAIMS_FILE); optional")
	pkg := flags.String("package", "desktop", "package name for the events")
	out := flags.String("out", "-", "events file (- for standard output)")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	if *output == "" {
		return 2, errors.New("-test-output is required")
	}
	of, err := os.Open(*output)
	if err != nil {
		return 2, err
	}
	defer of.Close()
	var cf io.Reader = strings.NewReader("")
	if *claims != "" {
		f, err := os.Open(*claims)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return 2, err
		}
		if err == nil {
			defer f.Close()
			cf = f
		}
	}
	evs, err := cargoEvents(of, cf, *pkg, time.Now().UTC())
	if err != nil {
		return 2, err
	}
	w := stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			return 2, err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	failed := false
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			return 2, err
		}
		if e.Action == "fail" && e.Test != "" {
			failed = true
		}
	}
	if failed {
		return 1, nil
	}
	return 0, nil
}

// cargoEvents joins cargo's result lines and the claims file into events.
func cargoEvents(testOutput, claims io.Reader, pkg string, now time.Time) ([]event, error) {
	tests := map[string]*cargoTest{}
	get := func(name string) *cargoTest {
		t := tests[name]
		if t == nil {
			t = &cargoTest{}
			tests[name] = t
		}
		return t
	}
	sc := bufio.NewScanner(testOutput)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		m := cargoResultLine.FindStringSubmatch(strings.TrimRight(sc.Text(), "\r"))
		if m == nil {
			continue
		}
		t := get(m[1])
		r := map[string]string{"ok": "pass", "FAILED": "fail", "ignored": "skip"}[m[2]]
		// The same path in two test binaries: a failure anywhere wins.
		if t.result != "fail" {
			t.result = r
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sc = bufio.NewScanner(claims)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 || (parts[1] != "PARTIAL" && parts[1] != "VERIFIES") {
			return nil, fmt.Errorf("claims file: malformed line %q", line)
		}
		if parts[0] == "main" || parts[0] == "unknown" || parts[0] == "" {
			return nil, fmt.Errorf("claims file: claim %q from a thread without a test name (run cargo test without --test-threads=1)", line)
		}
		for _, id := range strings.Fields(parts[2]) {
			if !idPattern.MatchString(id) {
				return nil, fmt.Errorf("claims file: %q is not a requirement ID", id)
			}
		}
		t := get(parts[0])
		t.claims = append(t.claims, parts[1]+": "+parts[2])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(tests))
	for n := range tests {
		names = append(names, n)
	}
	sort.Strings(names)
	var evs []event
	pkgFailed := false
	for _, n := range names {
		t := tests[n]
		evs = append(evs, event{Time: now, Action: "run", Package: pkg, Test: n})
		for _, c := range t.claims {
			evs = append(evs, event{Time: now, Action: "output", Package: pkg, Test: n, Output: "    " + c + "\n"})
		}
		result := t.result
		if result == "" {
			evs = append(evs, event{Time: now, Action: "output", Package: pkg, Test: n, Output: "    no cargo test result for this test\n"})
			result = "fail"
		}
		if result == "fail" {
			pkgFailed = true
		}
		evs = append(evs, event{Time: now, Action: result, Package: pkg, Test: n})
	}
	final := "pass"
	if pkgFailed {
		final = "fail"
	}
	evs = append(evs, event{Time: now, Action: final, Package: pkg})
	return evs, nil
}
