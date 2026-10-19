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

const cargoOutput = `
running 4 tests
test state::tests::stale_data_is_unreachable_never_healthy ... ok
test tlspin::tests::accepts_only_the_gateway_ca_and_the_configured_name ... FAILED
test icons::tests::six_distinct_icons ... ok
test service::tests::slow ... ignored, needs a service manager

failures:

---- tlspin::tests::accepts_only_the_gateway_ca_and_the_configured_name stdout ----
PARTIAL: SR-2.8-5
thread 'tlspin::tests::accepts_only_the_gateway_ca_and_the_configured_name' panicked at src/tlspin.rs:1:1:

test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.40s
`

const cargoClaims = "state::tests::stale_data_is_unreachable_never_healthy\tPARTIAL\tFR-20.4\n" +
	"tlspin::tests::accepts_only_the_gateway_ca_and_the_configured_name\tPARTIAL\tSR-2.8-5\n" +
	"icons::tests::six_distinct_icons\tVERIFIES\tFR-20.2\n" +
	"console::tests::never_finished\tPARTIAL\tFR-20.6\n"

// TestCargoClaimsBecomeTestEvents: the Rust tests' claims and cargo's
// results become go test -json events that parseTestLog reads like Go
// test claims (FR-12.10): passing, failing and skipped tests keep their
// result, and a claiming test with no result line is failing.
func TestCargoClaimsBecomeTestEvents(t *testing.T) {
	reqtest.Partial(t, "FR-12.10")
	evs, err := cargoEvents(strings.NewReader(cargoOutput), strings.NewReader(cargoClaims), "desktop/macos", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
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
		claims []Claim
	}{
		"state::tests::stale_data_is_unreachable_never_healthy":              {"pass", []Claim{{"FR-20.4", true}}},
		"tlspin::tests::accepts_only_the_gateway_ca_and_the_configured_name": {"fail", []Claim{{"SR-2.8-5", true}}},
		"icons::tests::six_distinct_icons":                                   {"pass", []Claim{{"FR-20.2", false}}},
		"service::tests::slow":                                               {"skip", nil},
		"console::tests::never_finished":                                     {"fail", []Claim{{"FR-20.6", true}}},
	}
	if len(got) != len(want) {
		t.Fatalf("tests %v", got)
	}
	for name, w := range want {
		tr := got[name]
		if tr == nil {
			t.Fatalf("missing %s", name)
		}
		if tr.Result != w.result || tr.Package != "desktop/macos" {
			t.Errorf("%s: result %q package %q, want %q", name, tr.Result, tr.Package, w.result)
		}
		if len(tr.Claims) != len(w.claims) || (len(w.claims) > 0 && tr.Claims[0] != w.claims[0]) {
			t.Errorf("%s: claims %v, want %v", name, tr.Claims, w.claims)
		}
	}
	if len(log.Packages) != 1 || log.Packages[0].Result != "fail" {
		t.Fatalf("package result %+v", log.Packages)
	}
}

func TestCargoClaimsRefuseBadLines(t *testing.T) {
	reqtest.Partial(t, "FR-12.10")
	for _, bad := range []string{
		"main\tPARTIAL\tFR-20.4\n",             // --test-threads=1: no test name
		"a::b\tMAYBE\tFR-20.4\n",               // unknown kind
		"a::b\tPARTIAL\tnot-an-id\n",           // not a requirement ID
		"a::b PARTIAL FR-20.4\n",               // not tab-separated
		"unknown\tVERIFIES\tFR-20.4 FR-20.2\n", // unnamed thread
	} {
		if _, err := cargoEvents(strings.NewReader(cargoOutput), strings.NewReader(bad), "desktop", time.Unix(0, 0)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCargoSubcommandWritesEventsAndExitStatus(t *testing.T) {
	reqtest.Partial(t, "FR-12.10")
	dir := t.TempDir()
	outPath := filepath.Join(dir, "cargo.txt")
	if err := os.WriteFile(outPath, []byte("test a::passes ... ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	claimsPath := filepath.Join(dir, "claims.tsv")
	if err := os.WriteFile(claimsPath, []byte("a::passes\tPARTIAL\tFR-20.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evPath := filepath.Join(dir, "events.json")
	code, err := runCargo([]string{"-test-output", outPath, "-claims", claimsPath, "-package", "desktop/linux", "-out", evPath}, os.Stdout)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	b, _ := os.ReadFile(evPath)
	if !strings.Contains(string(b), `"Output":"    PARTIAL: FR-20.4\n"`) || !strings.Contains(string(b), `"Package":"desktop/linux"`) {
		t.Fatalf("events %s", b)
	}
	// A missing claims file is no claims; a failing test exits 1.
	if err := os.WriteFile(outPath, []byte("test a::fails ... FAILED\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, err = runCargo([]string{"-test-output", outPath, "-claims", filepath.Join(dir, "none.tsv"), "-out", evPath}, os.Stdout)
	if err != nil || code != 1 {
		t.Fatalf("failing run: code %d err %v", code, err)
	}
	if code, err := runCargo(nil, os.Stdout); code != 2 || err == nil {
		t.Fatalf("no -test-output: %d %v", code, err)
	}
}
