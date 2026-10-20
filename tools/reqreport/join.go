package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// The join subcommand claims a requirement whose verification statement
// needs tests on several platforms, each of which claims it only partly
// (FR-12.10): it reads the events of those tests, which other jobs wrote,
// and writes one test that claims the requirement in full when every
// named test passed:
//
//	go run ./tools/reqreport join -test desktop/join::fr_20_8 -full FR-20.8 \
//	    -need build/desktop-e2e-linux-test.json:e2e::linux::introduction_then_setup \
//	    -need build/desktop-setup-macos-test.json:setup::tests::first_run_setup_with_the_real_smcpctl \
//	    -out build/desktop-join-test.json
//
// The test fails when a named test failed, and is skipped, claiming
// nothing, when a file or test is missing or was skipped (a platform's job
// did not run). -out is appended to, so several joins share one file.

type needList []string

func (n *needList) String() string     { return strings.Join(*n, ",") }
func (n *needList) Set(v string) error { *n = append(*n, v); return nil }

func runJoin(args []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet("join", flag.ContinueOnError)
	test := flags.String("test", "", "name of the joined test")
	pkg := flags.String("package", "desktop/join", "package name for the events")
	full := flags.String("full", "", "requirement IDs claimed in full, space-separated")
	why := flags.String("why", "", "what the named tests cover together, printed with the claim")
	out := flags.String("out", "-", "events file to append to (- for standard output)")
	var needs needList
	flags.Var(&needs, "need", "<events file>:<test name>; repeatable")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	if *test == "" || *full == "" || len(needs) == 0 {
		return 2, errors.New("-test, -full and at least one -need are required")
	}
	for _, id := range strings.Fields(*full) {
		if !idPattern.MatchString(id) {
			return 2, fmt.Errorf("%q is not a requirement ID", id)
		}
	}
	results := map[string]string{}
	for _, n := range needs {
		file, name, ok := strings.Cut(n, ":")
		if !ok {
			return 2, fmt.Errorf("-need %q: want <file>:<test>", n)
		}
		results[n] = testResult(file, name)
	}
	evs := joinEvents(*test, *pkg, strings.Fields(*full), *why, needs, results, time.Now().UTC())
	w := stdout
	if *out != "-" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return 2, err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			return 2, err
		}
		if e.Action == "output" {
			fmt.Fprint(os.Stderr, e.Test+": "+strings.TrimLeft(e.Output, " "))
		}
	}
	return 0, nil
}

// testResult is the result of one test in an events file: pass, fail,
// skip, or "missing".
func testResult(file, name string) string {
	f, err := os.Open(file)
	if err != nil {
		return "missing"
	}
	defer f.Close()
	log, err := parseTestLog(f)
	if err != nil {
		return "missing"
	}
	result := "missing"
	for _, t := range log.Tests {
		if t.Name != name {
			continue
		}
		switch {
		case t.Result == "fail" || t.Result == "":
			return "fail"
		case t.Result == "pass":
			result = "pass"
		case result == "missing":
			result = t.Result
		}
	}
	return result
}

// joinEvents is the joined test: pass when every named test passed, fail
// when one failed, skip otherwise.
func joinEvents(test, pkg string, full []string, why string, needs []string, results map[string]string, now time.Time) []event {
	evs := []event{{Time: now, Action: "run", Package: pkg, Test: test}}
	say := func(s string) {
		evs = append(evs, event{Time: now, Action: "output", Package: pkg, Test: test, Output: "    " + s + "\n"})
	}
	result := "pass"
	for _, n := range needs {
		r := results[n]
		say(n + " " + r)
		switch {
		case r == "fail":
			result = "fail"
		case r != "pass" && result != "fail":
			result = "skip"
		}
	}
	if result != "skip" {
		say(markerFull + " " + strings.Join(full, " "))
		if why != "" {
			say(why)
		}
	}
	final := "pass"
	if result == "fail" {
		final = "fail"
	}
	return append(evs, event{Time: now, Action: result, Package: pkg, Test: test}, event{Time: now, Action: final, Package: pkg})
}
