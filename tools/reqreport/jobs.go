package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The jobs subcommand turns the results of the installers workflow's jobs
// (.github/workflows/installers.yml) into `go test -json` events with
// requirement claims (FR-12.10), as the cargo subcommand does for the Rust
// tests:
//
//	go run ./tools/reqreport jobs -needs needs.json -artifacts build/installers \
//	    -package desktop/installers -out build/desktop-installers-test.json
//
// Each job runs one smoke script on the runners of its platforms
// (scripts/package-smoke.sh, desktop-smoke.sh, msi-smoke.ps1,
// desktop-msi-smoke.ps1); a job that ends in success passed every check
// of its script. A claim below names the jobs whose checks together cover
// a requirement's verification statement, and becomes one test: it passes
// when every job passed and its inspection checks hold, fails when a job
// failed or a check does not hold, and is skipped when a job did not run
// (a macOS job without a runner on a pull request, docs/ci.md "macOS
// runners"), which claims nothing. -needs is the workflow's needs context
// as JSON (toJSON(needs)); a job with an "outcome" output (the macOS
// workflows: passed, failed, unavailable) is judged by it. -artifacts is
// the directory holding every installer the run built.

// jobClaim is one claiming test made from job results.
type jobClaim struct {
	Test    string
	Jobs    []string
	Full    []string
	Partial []string
	// Contains: repository files that must contain each string (an
	// inspection the verification statement names).
	Contains map[string][]string
	// NoArtifact: installer file name patterns that must not be among
	// the run's installers; Artifact: patterns that must be.
	NoArtifact, Artifact []string
	// Why: what the jobs check, printed with the result.
	Why string
}

// installerClaims are the claims of the installers workflow. The jobs and
// what their scripts check are listed in installers.yml.
var installerClaims = []jobClaim{
	{
		Test: "installers::macos_pkg_and_dmg",
		Jobs: []string{"smoke-macos", "desktop-macos"},
		Full: []string{"FR-20.17"},
		// FR-20.26 also asks for the start after the Open Anyway approval,
		// which needs a person at the Mac (docs/verification/gap-list.md).
		Partial: []string{"FR-20.26"},
		Why:     ".pkg on macOS arm64: the six commands linked from /usr/local/bin, root-owned, ad-hoc signed, each reporting the version; .dmg: mounted, the application copied out, started, its bundled commands found with the version, every executable and the bundle ad-hoc signed",
	},
	{
		Test: "installers::linux_packages",
		Jobs: []string{"smoke-linux", "smoke-desktop-linux"},
		Full: []string{"FR-20.18"},
		Why:  "smcp .deb (Ubuntu 24.04) and .rpm (Fedora) on amd64 and arm64: installed alone with no other package, commands in /usr/bin with the version; smcp-desktop .deb and .rpm: refused without smcp and with smcp of another version, installed with smcp, the application started",
	},
	{
		Test:       "installers::appimage",
		Jobs:       []string{"smoke-desktop-linux"},
		Full:       []string{"FR-20.19"},
		NoArtifact: []string{"*.flatpak", "*.flatpakref", "*.flatpakrepo"},
		Artifact:   []string{"smcp-desktop_*_linux_amd64.AppImage", "smcp-desktop_*_linux_arm64.AppImage"},
		Why:        "AppImage on Ubuntu 24.04 (amd64, arm64) and Arch Linux (no dpkg, no rpm): started, the six bundled commands found, setup offers the Standalone profile only; on Ubuntu setup's smcpctl install from the mounted image makes a systemd user unit that runs copies outside the image and starts again after the image is unmounted; no Flatpak among the installers",
	},
	{
		Test: "installers::windows_msi",
		Jobs: []string{"smoke-windows", "build-desktop-windows"},
		// FR-20.20 also asks for a recorded Windows 11 x64 host, and
		// FR-20.1 for the tray icon against a running Gateway
		// (docs/verification/gap-list.md).
		Partial: []string{"FR-20.20", "FR-20.1"},
		Why:     "smcp and smcp-desktop .msi on windows-latest (x64) and windows-11-arm (arm64): installed with msiexec /qn while Windows Installer is blocked from the network and tries no connection, files under %ProgramFiles%, version, no service registered; smcp-desktop: WebView2 bootstrapper not run, smcp scheme registered, the application started, its console window accepting a listener of the configured CA and refusing one of another CA; removed",
	},
	{
		Test: "installers::files_only",
		Jobs: []string{"smoke-linux", "smoke-macos", "smoke-windows", "smoke-desktop-linux", "build-desktop-windows", "desktop-macos"},
		Full: []string{"FR-20.21"},
		Why:  "every package installed on a clean runner creates no CP-46 directory, unit, account or process; the smcp .deb, .rpm and .pkg and the smcp-desktop .deb and .rpm installed over an installation of the previous release (v1.2.0) with a Gateway state, the .msi packages (no previous Windows release) over a state made by the same build: configuration, keys, policy, journal and backups byte-for-byte unchanged",
	},
	{
		Test: "installers::removal_keeps_evidence",
		Jobs: []string{"smoke-linux", "smoke-macos", "smoke-windows"},
		Full: []string{"FR-20.22"},
		Contains: map[string][]string{
			"docs/install.md": {"smcpctl uninstall --purge", "smcpctl uninstall"},
		},
		Why: "on Ubuntu, Fedora, macOS and Windows: set up, journal and backup, package removed: package files gone, the system service (systemd unit, Windows machine-mode service) stopped and removed, a per-user unit left running, configuration, journal, key and backups kept; a fresh installation verifies the kept journal",
	},
	{
		Test: "installers::installed_code_not_writable",
		Jobs: []string{"smoke-linux", "smoke-macos", "smoke-windows", "build-desktop-windows", "smoke-desktop-linux", "desktop-macos"},
		Full: []string{"SR-4.11-2"},
		Why:  ".pkg, .deb and .rpm: every installed file owned by root and not writable by the user, a write as the user refused; .msi: every installed file writable only by SYSTEM, Administrators and TrustedInstaller, and not by a standard user; .dmg copy and AppImage: smcpctl doctor reports the writable binaries",
	},
}

// needsJob is one job of the needs context.
type needsJob struct {
	Result  string            `json:"result"`
	Outputs map[string]string `json:"outputs"`
}

// jobState is pass, fail or skip.
func jobState(j needsJob, ok bool) string {
	if !ok {
		return "skip"
	}
	if o, has := j.Outputs["outcome"]; has && o != "" {
		switch o {
		case "passed":
			return "pass"
		case "failed":
			return "fail"
		}
		return "skip"
	}
	switch j.Result {
	case "success":
		return "pass"
	case "failure":
		return "fail"
	}
	return "skip"
}

func runJobs(args []string, stdout io.Writer) (int, error) {
	flags := flag.NewFlagSet("jobs", flag.ContinueOnError)
	needsFile := flags.String("needs", "", "the workflow's needs context as JSON")
	artifacts := flags.String("artifacts", "", "directory with the run's installers")
	root := flags.String("root", ".", "repository root for the inspection checks")
	pkg := flags.String("package", "desktop/installers", "package name for the events")
	out := flags.String("out", "-", "events file (- for standard output)")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	if *needsFile == "" {
		return 2, errors.New("-needs is required")
	}
	b, err := os.ReadFile(*needsFile)
	if err != nil {
		return 2, err
	}
	var needs map[string]needsJob
	if err := json.Unmarshal(b, &needs); err != nil {
		return 2, fmt.Errorf("%s: %w", *needsFile, err)
	}
	var names []string
	if *artifacts != "" {
		err := filepath.WalkDir(*artifacts, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				names = append(names, d.Name())
			}
			return err
		})
		if err != nil {
			return 2, err
		}
	}
	evs := jobEvents(installerClaims, needs, names, os.DirFS(*root), *pkg, time.Now().UTC())
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
		if e.Action == "output" {
			fmt.Fprint(os.Stderr, e.Test+": "+strings.TrimLeft(e.Output, " "))
		}
	}
	if failed {
		return 1, nil
	}
	return 0, nil
}

// jobEvents judges each claim from the jobs' results, the run's installer
// file names and the repository files.
func jobEvents(claims []jobClaim, needs map[string]needsJob, artifacts []string, repo fs.FS, pkg string, now time.Time) []event {
	var evs []event
	pkgFailed := false
	for _, c := range claims {
		evs = append(evs, event{Time: now, Action: "run", Package: pkg, Test: c.Test})
		say := func(s string) {
			evs = append(evs, event{Time: now, Action: "output", Package: pkg, Test: c.Test, Output: "    " + s + "\n"})
		}
		result := "pass"
		var states []string
		for _, j := range c.Jobs {
			job, ok := needs[j]
			st := jobState(job, ok)
			states = append(states, j+" "+st)
			switch {
			case st == "fail":
				result = "fail"
			case st == "skip" && result != "fail":
				result = "skip"
			}
		}
		say("jobs: " + strings.Join(states, ", "))
		if result == "pass" {
			for _, problem := range jobChecks(c, artifacts, repo) {
				say(problem)
				result = "fail"
			}
		}
		if result != "skip" {
			if len(c.Full) > 0 {
				say(markerFull + " " + strings.Join(c.Full, " "))
			}
			if len(c.Partial) > 0 {
				say(markerPartial + " " + strings.Join(c.Partial, " "))
			}
			say(c.Why)
		}
		if result == "fail" {
			pkgFailed = true
		}
		evs = append(evs, event{Time: now, Action: result, Package: pkg, Test: c.Test})
	}
	final := "pass"
	if pkgFailed {
		final = "fail"
	}
	return append(evs, event{Time: now, Action: final, Package: pkg})
}

// jobChecks returns the inspection checks of a claim that do not hold.
func jobChecks(c jobClaim, artifacts []string, repo fs.FS) []string {
	var problems []string
	files := make([]string, 0, len(c.Contains))
	for f := range c.Contains {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := fs.ReadFile(repo, f)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		for _, s := range c.Contains[f] {
			if !strings.Contains(string(b), s) {
				problems = append(problems, fmt.Sprintf("%s does not contain %q", f, s))
			}
		}
	}
	for _, pat := range c.NoArtifact {
		for _, n := range artifacts {
			if ok, _ := filepath.Match(pat, n); ok {
				problems = append(problems, fmt.Sprintf("the installers include %s", n))
			}
		}
	}
	for _, pat := range c.Artifact {
		found := false
		for _, n := range artifacts {
			if ok, _ := filepath.Match(pat, n); ok {
				found = true
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("no installer matches %s", pat))
		}
	}
	return problems
}
