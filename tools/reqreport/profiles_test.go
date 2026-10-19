package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// profileRun is one CI job's go test -json result file and the cmd/smcpctl
// tests that must have passed in it, each with a phrase its output must
// contain (the platform the test ran on).
type profileRun struct {
	name  string
	file  string
	tests map[string]string
}

// checkProfileRuns reports what is missing from the runs: a file, a test
// that did not pass (or also failed), or a test whose output lacks the
// phrase.
func checkProfileRuns(runs []profileRun) error {
	var problems []string
	for _, r := range runs {
		f, err := os.Open(r.file)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", r.name, err))
			continue
		}
		passed, failed, output := map[string]bool{}, map[string]bool{}, map[string]*strings.Builder{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var e event
			if json.Unmarshal(sc.Bytes(), &e) != nil || !strings.HasSuffix(e.Package, "/cmd/smcpctl") || e.Test == "" {
				continue
			}
			switch e.Action {
			case "pass":
				passed[e.Test] = true
			case "fail":
				failed[e.Test] = true
			case "output":
				if output[e.Test] == nil {
					output[e.Test] = &strings.Builder{}
				}
				output[e.Test].WriteString(e.Output)
			}
		}
		f.Close()
		for test, phrase := range r.tests {
			switch {
			case failed[test]:
				problems = append(problems, fmt.Sprintf("%s: %s failed", r.name, test))
			case !passed[test]:
				problems = append(problems, fmt.Sprintf("%s: %s did not pass", r.name, test))
			case output[test] == nil || !strings.Contains(output[test].String(), phrase):
				problems = append(problems, fmt.Sprintf("%s: the output of %s lacks %q", r.name, test, phrase))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// installProfileRuns are the runs that together cover FR-13.4 and FR-13.11
// in both profiles.
func installProfileRuns(macos, linux, enforced string) []profileRun {
	return []profileRun{
		// Standalone, launchd on macOS arm64 and a systemd user unit on
		// Ubuntu: install, a second install that reports every step present
		// and changes no configuration, key, policy, journal or unit file,
		// uninstall that removes the unit and binaries and keeps the journal
		// and the evidence key, and journal verify from another smcpctl
		// pointed at the kept journal and key (scripts/ci-install-standalone.sh).
		{"install-standalone (macOS)", macos, map[string]string{"TestInstallStandaloneServiceManager": "==> install-standalone: passed (darwin)"}},
		{"install-standalone (Linux)", linux, map[string]string{"TestInstallStandaloneServiceManager": "==> install-standalone: passed (linux)"}},
		// Enforced on the linux-integration host: install twice with every
		// step present and no file changed the second time; uninstall that
		// removes the units, binaries, nftables table and AppArmor profiles
		// and keeps the journal and evidence key, which another smcpctl
		// verifies; a Standalone uninstall beside it removes nothing of it.
		{"linux-integration (Enforced)", enforced, map[string]string{
			"TestEnforcedInstallOnHost":                "none created or updated",
			"TestEnforcedUninstallAndPurgeOnHost":      "last journal segment",
			"TestStandaloneUninstallKeepsEnforcedHost": "kept: system units, nftables table inet smcp",
		}},
	}
}

// TestInstallProfilesEvidence claims FR-13.4 (idempotent install) and
// FR-13.11 (uninstall) in full when, in the same CI run, the Standalone
// install, re-install and uninstall passed on macOS arm64 and Ubuntu and the
// Enforced install, re-install and uninstall passed on the Ubuntu host of
// linux-integration. Each of those tests claims its profile's half
// (partial); the status job runs this test on their result files
// (SMCP_INSTALL_EVIDENCE_MACOS, _LINUX and _ENFORCED) and merges its result
// with theirs.
func TestInstallProfilesEvidence(t *testing.T) {
	macos, linux, enforced := os.Getenv("SMCP_INSTALL_EVIDENCE_MACOS"), os.Getenv("SMCP_INSTALL_EVIDENCE_LINUX"), os.Getenv("SMCP_INSTALL_EVIDENCE_ENFORCED")
	if macos == "" || linux == "" || enforced == "" {
		t.Skip("reads the install-standalone and linux-integration results of a CI run; set SMCP_INSTALL_EVIDENCE_MACOS, _LINUX and _ENFORCED (status job)")
	}
	reqtest.Verifies(t, "FR-13.4", "FR-13.11")
	if err := checkProfileRuns(installProfileRuns(macos, linux, enforced)); err != nil {
		t.Fatal(err)
	}
}

// TestCheckProfileRuns: the check accepts passing tests with their phrase
// and rejects a missing file, a test that failed, a test that never ran and
// output without the platform phrase.
func TestCheckProfileRuns(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, events ...event) string {
		p := filepath.Join(dir, name)
		var b strings.Builder
		for _, e := range events {
			j, _ := json.Marshal(e)
			b.Write(j)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const pkg = "github.com/ethan03805/secure-mcp-gateway/cmd/smcpctl"
	ok := write("ok.json",
		event{Action: "output", Package: pkg, Test: "TestA", Output: "==> install-standalone: passed (darwin)\n"},
		event{Action: "pass", Package: pkg, Test: "TestA"})
	failed := write("failed.json",
		event{Action: "output", Package: pkg, Test: "TestA", Output: "==> install-standalone: passed (darwin)\n"},
		event{Action: "fail", Package: pkg, Test: "TestA"})
	other := write("other.json",
		event{Action: "output", Package: pkg, Test: "TestA", Output: "==> install-standalone: passed (linux)\n"},
		event{Action: "pass", Package: pkg, Test: "TestA"})
	wrongPkg := write("pkg.json",
		event{Action: "output", Package: "example.com/x", Test: "TestA", Output: "==> install-standalone: passed (darwin)\n"},
		event{Action: "pass", Package: "example.com/x", Test: "TestA"})
	want := map[string]string{"TestA": "passed (darwin)"}
	if err := checkProfileRuns([]profileRun{{"ok", ok, want}}); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]string{"missing": filepath.Join(dir, "none.json"), "failed": failed, "phrase": other, "package": wrongPkg} {
		if err := checkProfileRuns([]profileRun{{name, file, want}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := checkProfileRuns([]profileRun{{"absent test", ok, map[string]string{"TestB": "x"}}}); err == nil {
		t.Error("a test that never ran accepted")
	}
}
