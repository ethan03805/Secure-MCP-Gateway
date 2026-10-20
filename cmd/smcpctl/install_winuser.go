package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

// The per-user installation on Windows (SRS FR-21.6, CP-46): the files
// that stand for its service definition, kept in the configuration
// directory so that uninstall and upgrade find them like a launchd plist.
const (
	winTaskFile = "smcpd-task.xml" // the registered Task Scheduler definition
	winRunFile  = "smcpd-run.txt"  // the command line of the Run-key fallback
)

// winHooks are the Windows calls of the per-user installation, replaced by
// tests (cmd/smcpctl runs its install tests on every platform).
type winHooks struct {
	version       func() winsvc.Version
	userSID       func() (string, error)
	secureDir     func(dir string) error // CP-46: protected DACL, this user, SYSTEM, Administrators
	setRunValue   func(commandLine string) error
	startDetached func(exe string, args []string, dir string) (int, error)
	// launchSupported is pipeline.SubprocessSupported: nil once server
	// instances can be started on this platform.
	launchSupported func() error
}

// exeName adds the .exe suffix of a Windows executable.
func exeName(goos, name string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

func (in *installer) localAppData() string {
	if v := in.getenv("LOCALAPPDATA"); v != "" && filepath.IsAbs(v) {
		return v
	}
	return filepath.Join(in.home, "AppData", "Local")
}

// windowsUser installs the per-user mode (FR-21.6): CP-46 directories with
// protected DACLs (FR-21.5), keys protected with DPAPI (FR-21.10), the
// configuration, and a Task Scheduler task with a logon trigger for this
// user's SID, or, when Windows refuses the task to the user, the Run-key
// fallback. smcpd runs under its -supervise mode, which restarts it after
// a failure.
func (in *installer) windowsUser() error {
	v := in.win.version()
	if err := winsvc.CheckVersion(v); err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	l, err := in.layout()
	if err != nil {
		return err
	}
	if in.binDir, err = filepath.Abs(in.binDir); err != nil {
		return err
	}
	smcpdExe, refExe := exeName(in.goos, "smcpd"), exeName(in.goos, "smcp-refserver")
	// Until the FR-21.11 launcher exists no server instance can start on
	// Windows, and smcpd refuses to start with a server it cannot launch;
	// the installation then configures no server.
	noRef := in.win.launchSupported() != nil
	need := []string{smcpdExe}
	if !noRef {
		need = append(need, refExe)
	}
	if err := in.needBinaries(need...); err != nil {
		return err
	}
	exports := filepath.Join(filepath.Dir(l.cfgDir), "exports")
	for _, d := range []string{l.cfgDir, l.stateDir, l.logDir, exports} {
		if err := in.ensureDir(d, 0o700); err != nil {
			return err
		}
		if err := in.win.secureDir(d); err != nil {
			return fmt.Errorf("access control list of %s: %w", d, err)
		}
	}
	in.step("secured", "directories (inheritance disabled; this user, SYSTEM and Administrators only)")

	o := in.boot
	o.dir, o.stateDir, o.quiet, o.noRefServer = l.cfgDir, l.stateDir, true, noRef
	if o.sandbox == "" {
		o.sandbox = l.sandbox
	}
	if o.refserver == "" && !noRef {
		o.refserver = filepath.Join(in.binDir, refExe)
	}
	o.extraConfig = fmt.Sprintf(`
# Written by smcpctl install (FR-21.6). Windows installations run the
# Standalone profile and are not enforced (SR-4-2).
[profile]
mode = "standalone"

[log]
file = %q
`, filepath.Join(l.logDir, "smcpd.log"))
	res, err := runBootstrap(o, in.out)
	if err != nil {
		return err
	}
	in.step(verb(res.keysCreated), "keys (DPAPI) and TLS certificates in "+res.stateDir)
	in.step(verb(res.cfgCreated), "configuration "+res.cfgPath)
	in.step(verb(res.polCreated), "policy "+res.polPath)
	if noRef && res.cfgCreated {
		fmt.Fprintln(in.out, "note: no MCP server is configured: server instances cannot be started on Windows yet (SRS FR-21.11).")
	}
	cfg, err := config.Load(res.cfgPath)
	if err != nil {
		return err
	}

	smcpd := filepath.Join(in.binDir, smcpdExe)
	args := []string{"-supervise", "-config", res.cfgPath}
	sid, err := in.win.userSID()
	if err != nil {
		return err
	}
	task, err := winsvc.TaskXML(sid, smcpd, res.cfgPath, l.cfgDir)
	if err != nil {
		return err
	}
	taskFile := filepath.Join(l.cfgDir, winTaskFile)
	runFile := filepath.Join(l.cfgDir, winRunFile)
	tv, err := ensureFile(taskFile, winsvc.TaskFile(task), 0o600)
	if err != nil {
		return err
	}
	if err := in.run("schtasks", "/create", "/tn", winsvc.TaskName, "/xml", taskFile, "/f"); err != nil {
		// FR-21.6: Windows may refuse a logon task to a standard user.
		_ = os.Remove(taskFile)
		cmdline := winsvc.CommandLine(append([]string{smcpd}, args...)...)
		if err := in.win.setRunValue(cmdline); err != nil {
			return fmt.Errorf("the Task Scheduler task and the Run key were both refused: %w", err)
		}
		rv, err := ensureFile(runFile, []byte(cmdline+"\n"), 0o600)
		if err != nil {
			return err
		}
		in.step(rv, `logon start HKCU\Software\Microsoft\Windows\CurrentVersion\Run\`+winsvc.RunValue)
		fmt.Fprintln(in.out, "note: Windows refused the Task Scheduler task, so smcpd starts at logon from the Run key. "+
			"Windows does not restart it after a failure; smcpd's supervisor restarts a failed Gateway, but nothing restarts the supervisor.")
	} else {
		_ = os.Remove(runFile)
		in.step(tv, "Task Scheduler task "+winsvc.TaskName+" (at logon of this user; definition "+taskFile+")")
	}

	if in.noStart {
		in.step("skipped", "start and health check (--no-start)")
	} else {
		if daemonUp(cfg) {
			in.step("present", "smcpd running")
		} else {
			pid, err := in.win.startDetached(smcpd, args, l.cfgDir)
			if err != nil {
				return fmt.Errorf("start smcpd: %w", err)
			}
			in.step("created", fmt.Sprintf("smcpd started (supervisor pid %d)", pid))
		}
		if err := in.verifyHealth(cfg); err != nil {
			return err
		}
	}
	fmt.Fprintf(in.out, `
This installation is not enforced (Windows per-user mode, label "not
enforced"): MCP servers run as your user, and an agent running as your
user can read the Gateway's state. DPAPI protects the keys against a copy
to another account or computer, not against your own programs.

Configuration: %s
Check health:  smcpctl health --config %s
Remove:        smcpctl uninstall --config %s
`, res.cfgPath, winsvc.CommandLine(res.cfgPath), winsvc.CommandLine(res.cfgPath))
	return nil
}

// winUnitFiles are the per-user service definitions on Windows.
func winUnitFiles(cfgDir string) []unitFile {
	var out []unitFile
	for _, u := range []struct{ name, kind string }{{winTaskFile, "win-task"}, {winRunFile, "win-run"}} {
		p := filepath.Join(cfgDir, u.name)
		_, err := os.Stat(p)
		out = append(out, unitFile{path: p, kind: u.kind, exists: err == nil})
	}
	return out
}

// isWinUnit reports whether a unit kind is a Windows per-user definition.
func isWinUnit(kind string) bool { return strings.HasPrefix(kind, "win-") }
