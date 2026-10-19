package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestUninstallScopeByProfile: each profile's uninstall removes only the
// unit files its own install wrote. A Standalone (or "auto") installation
// removes the user's launchd agent or systemd user unit and never the
// system units, the nftables ruleset or its loader unit of an Enforced
// installation on the same host; the Enforced uninstall removes the system
// units and leaves a user's Standalone unit alone.
func TestUninstallScopeByProfile(t *testing.T) {
	reqtest.Partial(t, "FR-13.11")
	for _, c := range []struct {
		mode     string
		enforced bool
	}{{"standalone", false}, {"auto", false}, {"", false}, {"enforced", true}} {
		s := scopeFor(c.mode)
		if s.enforced != c.enforced {
			t.Fatalf("mode %q: enforced scope %v", c.mode, s.enforced)
		}
		for kind, enforcedOwns := range map[string]bool{
			"launchd": false, "systemd-user": false,
			"systemd-system": true, "systemd-aux": true, "nft-ruleset": true,
		} {
			if got, want := s.removesUnit(kind), enforcedOwns == c.enforced; got != want {
				t.Errorf("mode %q removes %s unit: %v, want %v", c.mode, kind, got, want)
			}
		}
	}
}

// fakeHostCommands puts recording stand-ins for the host tools uninstall
// calls (sudo, nft, systemctl, loginctl, apparmor_parser, launchctl) first
// on PATH. nft answers `list table` with success, as on a host where the
// Enforced profile's table exists. It returns the log file.
func fakeHostCommands(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	rec := "#!/bin/sh\nprintf '%s\\n' \"$(basename \"$0\") $*\" >> " + log + "\nexit 0\n"
	for _, n := range []string{"nft", "systemctl", "loginctl", "apparmor_parser", "launchctl", "userdel", "pkill"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(rec), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sudo := "#!/bin/sh\nprintf '%s\\n' \"sudo $*\" >> " + log + "\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(sudo), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// TestStandaloneUninstallLeavesEnforcedTable reproduces the defect where a
// Standalone `smcpctl uninstall` with passwordless sudo deleted the system
// nftables table `inet smcp` of an Enforced installation on the same host:
// with the host tools replaced by recorders (nft reports the table
// present), a Standalone uninstall makes no nft, apparmor_parser or userdel
// call, also with --purge, while an Enforced uninstall deletes the table.
func TestStandaloneUninstallLeavesEnforcedTable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nftables and the Enforced profile exist on Linux only")
	}
	reqtest.Partial(t, "FR-13.11")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	log := fakeHostCommands(t)
	run := func(mode string, purge bool) string {
		t.Helper()
		_ = os.Remove(log)
		dir, cfg := instance(t)
		f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("\n[profile]\nmode = \"" + mode + "\"\n"); err != nil {
			t.Fatal(err)
		}
		f.Close()
		bin := t.TempDir()
		args := []string{"--config", cfg, "--bin-dir", bin}
		stdin := ""
		if purge {
			id, err := keys.EnsureInstallationID(filepath.Join(dir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			args, stdin = append([]string{"--purge"}, args...), id+"\n"
		}
		var out bytes.Buffer
		if err := uninstallCmd(args, strings.NewReader(stdin), &out); err != nil {
			t.Fatalf("uninstall (%s): %v\n%s", mode, err, out.String())
		}
		calls, _ := os.ReadFile(log)
		t.Logf("%s uninstall:\n%s\ncalls:\n%s", mode, out.String(), calls)
		return string(calls)
	}
	for _, purge := range []bool{false, true} {
		calls := run("standalone", purge)
		for _, tool := range []string{"nft ", "apparmor_parser", "userdel", "loginctl"} {
			if strings.Contains(calls, tool) {
				t.Errorf("Standalone uninstall (purge %v) called %s:\n%s", purge, tool, calls)
			}
		}
	}
	if calls := run("enforced", false); !strings.Contains(calls, "nft delete table inet smcp") {
		t.Errorf("Enforced uninstall did not delete the table:\n%s", calls)
	}
}
