package acceptance

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// cliStep is one exercised smcpctl subcommand and what was checked.
type cliStep struct {
	Subcommand string   `json:"subcommand"`
	Args       []string `json:"args"`
	Check      string   `json:"check"`
	Pass       bool     `json:"pass"`
	Output     string   `json:"output,omitempty"`
}

// TestAdminCLIDemonstration exercises the FR-12.7 subcommands of smcpctl on
// one bootstrapped installation of the real binaries, in the profile the
// suite runs in (Standalone in the go job, Enforced in the
// acceptance-enforced job), and checks each one's documented outcome. It
// writes the steps as JSON to $SMCP_ADMIN_CLI_EVIDENCE/<profile>.json when
// that variable is set, as the Demonstration's evidence.
//
// Partial: install, upgrade and uninstall change the host (a service unit,
// in the Enforced profile root-owned identities and paths); they are
// exercised by TestInstallStandaloneServiceManager (install-standalone
// job), TestUpgradeAndRollback and TestEnforcedUninstallAndPurgeOnHost, not
// on this installation.
func TestAdminCLIDemonstration(t *testing.T) {
	reqtest.Partial(t, "FR-12.7")
	g := newGateway(t, options{})
	var steps []cliStep
	failed := false
	home := t.TempDir()
	run := func(args []string) (string, error) {
		// Harness configuration commands work on this user's client files:
		// they run with a temporary home directory.
		if args[0] != "client" && args[0] != "lockdown" && args[0] != "doctor" {
			return g.ctl(args...)
		}
		cmd := exec.Command(filepath.Join(binDir, "smcpctl"), append(args, "--config", g.cfg)...)
		cmd.Dir = g.dir
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
		var b bytes.Buffer
		cmd.Stdout, cmd.Stderr = &b, &b
		err := cmd.Run()
		return b.String(), err
	}
	step := func(sub, check string, ok func(out string, err error) bool, args ...string) string {
		t.Helper()
		out, err := run(args)
		pass := ok(out, err)
		s := cliStep{Subcommand: sub, Args: args, Check: check, Pass: pass}
		if len(out) > 2000 {
			s.Output = out[:2000]
		} else {
			s.Output = out
		}
		steps = append(steps, s)
		if !pass {
			failed = true
			t.Errorf("smcpctl %s: %s: err %v\n%s", strings.Join(args, " "), check, err, out)
		}
		return out
	}
	succeeds := func(want ...string) func(string, error) bool {
		return func(out string, err error) bool {
			if err != nil {
				return false
			}
			for _, w := range want {
				if !strings.Contains(out, w) {
					return false
				}
			}
			return true
		}
	}
	// bootstrap ran in newGateway; record its result.
	_, statErr := os.Stat(filepath.Join(g.state, "keys", "admin.token"))
	steps = append(steps, cliStep{Subcommand: "bootstrap", Args: []string{"bootstrap", "--dir", g.dir}, Check: "state, keys, TLS certificates, configuration and policy created", Pass: statErr == nil && fileExists(g.cfg) && fileExists(g.caFile)})
	if statErr != nil {
		t.Errorf("bootstrap: %v", statErr)
		failed = true
	}

	step("version", "prints the version", succeeds("smcp"), "version")
	step("config validate", "configuration and policy are valid", succeeds(), "config", "validate")
	step("config migrate", "nothing to migrate at this release's schema_version", succeeds("nothing to migrate"), "config", "migrate")

	g.start()
	profile := g.profile()
	step("health", "the health report is printed", succeeds("health: "), "health")
	step("reload", "the configuration is reloaded", succeeds(`"restart_required"`), "reload")
	step("keys rotate", "the listener certificate is rotated", succeeds(), "keys", "rotate", "tls")
	step("stop", "emergency stop is entered", succeeds(), "stop")
	step("health", "the report shows the emergency stop", succeeds("emergency"), "health")
	step("resume", "emergency stop is left", succeeds(), "resume")
	step("approvals", "the approvals are listed", succeeds(), "approvals", "list", "--state", "all")
	step("clients", "the remote client registrations are listed", succeeds(), "clients", "list")
	step("remote", "the Remote Access Profile state is shown", succeeds(), "remote", "status")
	step("trust", "the trust anchors are listed", succeeds("bootstrap-"), "trust", "list")
	step("package", "the imported revisions are listed with their states", succeeds("enabled"), "package", "list")
	step("client setup", "the harness configuration for Claude Code is planned (dry run)", succeeds(), "client", "setup", "claude-code", "--dry-run")
	step("lockdown", "the Claude Code lockdown profile is planned (dry run)", succeeds(), "lockdown", "apply", "claude-code", "--dry-run")
	step("doctor", "the doctor findings are reported as JSON", func(out string, _ error) bool {
		// Findings make doctor exit 1 with a last line on stderr; the
		// report before it is the JSON document.
		doc := strings.TrimSpace(out)
		if i := strings.LastIndex(doc, "\nsmcpctl: "); i >= 0 {
			doc = doc[:i]
		}
		return json.Valid([]byte(doc)) && strings.Contains(doc, `"kind"`)
	}, "doctor", "--json")
	pw := writeFile(t, t.TempDir(), "backup.pw", "admin cli demonstration passphrase\n", 0o600)
	step("backup", "an encrypted backup is written", succeeds("backup written"), "backup", "--passphrase-file", pw)
	time.Sleep(200 * time.Millisecond)
	g.stop()

	step("journal verify", "the journal verifies, with the key transition of the rotation", succeeds(), "journal", "verify")
	archives, _ := filepath.Glob(filepath.Join(g.dir, "backups", "*.age"))
	if len(archives) != 1 {
		t.Errorf("backups: %v", archives)
		failed = true
	} else {
		step("restore", "the backup is restored, the previous state kept", succeeds("previous state is kept"), "restore", "--archive", archives[0], "--passphrase-file", pw)
		step("journal verify", "the restored journal verifies", succeeds(), "journal", "verify")
	}
	g.start()
	step("health", "the restored Gateway starts and reports health", succeeds("health: "), "health")
	g.stop()

	if dir := os.Getenv("SMCP_ADMIN_CLI_EVIDENCE"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(map[string]any{"profile": profile, "passed": !failed, "steps": steps}, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, requestedProfile()+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range steps {
		t.Logf("%-16s pass=%v  %s", s.Subcommand, s.Pass, s.Check)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
