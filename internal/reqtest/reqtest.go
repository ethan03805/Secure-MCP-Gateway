// Package reqtest tags automated tests with the requirement IDs they verify
// (FR-12.10). A test calls Verifies with the IDs it fully verifies and
// Partial with the IDs it exercises only in part; the lines they log are
// parsed from `go test -json` output by tools/reqreport, which maps every
// requirement ID to the result of the tests that claim it.
//
// The rule for choosing between the two is strict: Verifies only when the
// test performs the requirement's verification statement against code that
// implements every clause of the requirement. Anything less is Partial, and
// the test comment says which clauses are missing.
package reqtest

import (
	"regexp"
	"strings"
	"testing"
)

// Marker is the prefix of the log line for full verification claims.
const Marker = "VERIFIES:"

// PartialMarker is the prefix of the log line for partial claims.
const PartialMarker = "PARTIAL:"

var idPattern = regexp.MustCompile(`^(FR-\d+(\.\d+)?|SR-\d+(\.\d+)?-\d+)$`)

func check(t testing.TB, fn string, ids []string) {
	t.Helper()
	if len(ids) == 0 {
		t.Fatalf("reqtest.%s: no requirement IDs given", fn)
	}
	for _, id := range ids {
		if !idPattern.MatchString(id) {
			t.Fatalf("reqtest.%s: %q is not a requirement ID", fn, id)
		}
	}
}

// Verifies declares that the calling test fully verifies the given
// requirement IDs. An ID that does not look like an SRS requirement ID fails
// the test, so a typo cannot silently produce an untracked claim.
func Verifies(t testing.TB, ids ...string) {
	t.Helper()
	check(t, "Verifies", ids)
	t.Log(Marker + " " + strings.Join(ids, " "))
}

// Partial declares that the calling test exercises the given requirement IDs
// without verifying every clause. Reports list these separately from full
// verification so that a requirement is never shown as met on partial
// evidence.
func Partial(t testing.TB, ids ...string) {
	t.Helper()
	check(t, "Partial", ids)
	t.Log(PartialMarker + " " + strings.Join(ids, " "))
}

// ScenarioMarker is the prefix of the log line for acceptance scenario
// claims (FR-19.4).
const ScenarioMarker = "SCENARIO:"

// Profiles a scenario can run in (SRS Section 2.5).
const (
	Standalone = "standalone"
	Enforced   = "enforced"
)

// Windows installation modes (SR-4-2). A scenario claimed in one of them is
// reported per mode next to the Enforced and Standalone results (FR-21.20)
// and never counts toward the release label.
const (
	WindowsUser    = "windows-user"
	WindowsMachine = "windows-machine"
	WSL2           = "wsl2"
)

// ScenarioNotRunMarker starts the log line of ScenarioNotRun.
const ScenarioNotRunMarker = "SCENARIO-NOT-RUN:"

func knownProfile(p string) bool {
	switch p {
	case Standalone, Enforced, WindowsUser, WindowsMachine, WSL2:
		return true
	}
	return false
}

// ScenarioNotRun records that the calling test cannot run the given
// scenarios in profile, a Windows installation mode, and why (FR-21.20:
// each scenario a mode cannot run is listed with its reason). The test
// then skips.
func ScenarioNotRun(t testing.TB, profile, reason string, ids ...string) {
	t.Helper()
	if profile != WindowsUser && profile != WindowsMachine && profile != WSL2 {
		t.Fatalf("reqtest.ScenarioNotRun: %q is not a Windows installation mode", profile)
	}
	for _, id := range ids {
		if !scenarioPattern.MatchString(id) {
			t.Fatalf("reqtest.ScenarioNotRun: %q is not a scenario ID AT-01 to AT-21", id)
		}
	}
	t.Log(ScenarioNotRunMarker + " " + strings.Join(ids, " ") + " profile=" + profile + " reason=" + strings.Join(strings.Fields(reason), " "))
}

var scenarioPattern = regexp.MustCompile(`^AT-(0[1-9]|1[0-9]|2[01])$`)

// Scenario declares that the calling test executes the given acceptance
// scenarios of SRS Appendix M (AT-01 to AT-21) in profile, which is
// Standalone or Enforced, or on Windows the installation mode (WindowsUser,
// WindowsMachine, WSL2), and must name the profile the test actually ran
// the Gateway in. tools/reqreport reports a scenario as passed in a profile
// when every test that claims it in that profile passed, and the release
// label (FR-19.3) counts only Enforced results. A scenario claim says
// nothing about the scenario's requirements; the test claims those with
// Verifies or Partial as usual.
func Scenario(t testing.TB, profile string, ids ...string) {
	t.Helper()
	if !knownProfile(profile) {
		t.Fatalf("reqtest.Scenario: profile %q is not %q, %q or a Windows installation mode", profile, Standalone, Enforced)
	}
	if len(ids) == 0 {
		t.Fatalf("reqtest.Scenario: no scenario IDs given")
	}
	for _, id := range ids {
		if !scenarioPattern.MatchString(id) {
			t.Fatalf("reqtest.Scenario: %q is not a scenario ID AT-01 to AT-21", id)
		}
	}
	t.Log(ScenarioMarker + " " + strings.Join(ids, " ") + " profile=" + profile)
}
