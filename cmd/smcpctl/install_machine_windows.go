//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

// CP-46 machine-mode local groups.
const (
	groupHarness   = "smcp-harness"
	groupOperators = "smcp-operators"
)

func programData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

func programFiles() string {
	if v := os.Getenv("ProgramFiles"); v != "" {
		return v
	}
	return `C:\Program Files`
}

// machineConfigPath is the machine-mode configuration (CP-46).
func machineConfigPath() string {
	return filepath.Join(programData(), "smcp-gateway", "config", "smcp.toml")
}

// windowsMachine installs the Windows machine mode (FR-21.6, FR-21.5,
// CP-46): binaries in %ProgramFiles%\smcp-gateway, configuration, state,
// logs and exports in %ProgramData%\smcp-gateway with the CP-46 DACLs,
// the local groups smcp-harness and smcp-operators (the installing user
// joins both), and the service smcpd under NT SERVICE\smcpd with
// automatic (delayed) start, an unrestricted service SID and restart on
// the first and second failure. The keys are made by the service at its
// first start, as DPAPI blobs of its own account (FR-21.10).
func (in *installer) windowsMachine() error {
	if !winsec.IsElevated() {
		return errors.New("the machine mode changes the system: run smcpctl install --machine from an elevated prompt (Run as administrator); nothing was changed")
	}
	if err := winsvc.CheckVersion(winsvc.HostVersion()); err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	var err error
	if in.binDir, err = filepath.Abs(in.binDir); err != nil {
		return err
	}
	if err := in.needBinaries("smcpd.exe"); err != nil {
		return err
	}
	binDst := filepath.Join(programFiles(), "smcp-gateway")
	if !strings.EqualFold(filepath.Clean(in.binDir), filepath.Clean(binDst)) {
		if err := os.MkdirAll(binDst, 0o755); err != nil {
			return err
		}
		for _, n := range releaseBinaries {
			src := filepath.Join(in.binDir, n+".exe")
			if _, err := os.Stat(src); err != nil {
				continue
			}
			err := packaging.CopyFile(src, filepath.Join(binDst, n+".exe"), 0o755)
			if err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			if err != nil {
				// An existing file is replaced through a temporary name.
				tmp := filepath.Join(binDst, n+".exe.new")
				_ = os.Remove(tmp)
				if err := packaging.CopyFile(src, tmp, 0o755); err != nil {
					return err
				}
				if err := os.Rename(tmp, filepath.Join(binDst, n+".exe")); err != nil {
					return fmt.Errorf("replace %s (stop the service first): %w", n, err)
				}
			}
		}
		in.step("present", "binaries in "+binDst)
	}
	smcpd := filepath.Join(binDst, "smcpd.exe")

	installer, err := winsec.ProcessUserSID()
	if err != nil {
		return err
	}
	for _, g := range []struct{ name, comment string }{
		{groupHarness, "Secure MCP Gateway: harness clients of the named pipe"},
		{groupOperators, "Secure MCP Gateway: operators who read evidence exports"},
	} {
		created, err := winsvc.EnsureLocalGroup(g.name, g.comment)
		if err != nil {
			return err
		}
		if err := winsvc.AddLocalGroupMember(g.name, installer); err != nil {
			return err
		}
		in.step(verb(created), "local group "+g.name+" (with the installing user)")
	}

	base := filepath.Join(programData(), "smcp-gateway")
	cfgDir, stateDir := filepath.Join(base, "config"), filepath.Join(base, "state")
	logDir, exports := filepath.Join(base, "log"), filepath.Join(base, "exports")
	for _, d := range []string{cfgDir, stateDir, logDir, exports} {
		if err := in.ensureDir(d, 0o700); err != nil {
			return err
		}
	}
	cfgPath := filepath.Join(cfgDir, "smcp.toml")
	created, err := winsvc.InstallService(smcpd, cfgPath)
	if err != nil {
		return err
	}
	in.step(verb(created), "service "+winsvc.ServiceName+" ("+winsvc.ServiceAccount+", automatic delayed start, restart on failure)")
	svcSID, err := winsec.LookupSID(winsvc.ServiceAccount)
	if err != nil {
		return err
	}
	operators, err := winsec.LookupSID(groupOperators)
	if err != nil {
		return err
	}
	admins := []winsec.Entry{{SID: winsec.SIDSystem, Access: winsec.FullControl}, {SID: winsec.SIDAdministrators, Access: winsec.FullControl}}
	acls := map[string][]winsec.Entry{
		cfgDir:   append(append([]winsec.Entry(nil), admins...), winsec.Entry{SID: svcSID, Access: winsec.ReadExecute}),
		stateDir: append(append([]winsec.Entry(nil), admins...), winsec.Entry{SID: svcSID, Access: winsec.FullControl}),
		logDir:   append(append([]winsec.Entry(nil), admins...), winsec.Entry{SID: svcSID, Access: winsec.FullControl}),
		exports:  append(append([]winsec.Entry(nil), admins...), winsec.Entry{SID: svcSID, Access: winsec.Modify}, winsec.Entry{SID: operators, Access: winsec.ReadExecute}),
	}
	for _, d := range []string{cfgDir, stateDir, logDir, exports} {
		if err := winsec.SetProtectedDACL(d, acls[d]); err != nil {
			return fmt.Errorf("access control list of %s: %w", d, err)
		}
	}
	in.step("secured", "directories (CP-46 machine-mode access control lists)")

	o := in.boot
	o.dir, o.stateDir, o.quiet, o.noKeys = cfgDir, stateDir, true, true
	o.noRefServer = in.win.launchSupported() != nil
	if o.sandbox == "" {
		o.sandbox = filepath.Join(base, "sandbox")
	}
	if o.refserver == "" && !o.noRefServer {
		o.refserver = filepath.Join(binDst, "smcp-refserver.exe")
	}
	o.extraConfig = fmt.Sprintf(`
# Written by smcpctl install --machine (FR-21.6). Windows installations run
# the Standalone profile and are not enforced (SR-4-2).
[profile]
mode = "standalone"

[log]
file = %q

[evidence]
export_dir = %q

# The UDS Harness Profile is served over this named pipe when enabled
# (FR-21.8); members of the local group smcp-harness may connect.
[uds]
enabled = false
path = '\\.\pipe\smcp-harness'
group = %q
`, filepath.Join(logDir, "smcpd.log"), exports, groupHarness)
	res, err := runBootstrap(o, in.out)
	if err != nil {
		return err
	}
	in.step(verb(res.cfgCreated), "configuration "+res.cfgPath)
	in.step(verb(res.polCreated), "policy "+res.polPath)
	if o.noRefServer && res.cfgCreated {
		fmt.Fprintln(in.out, "note: no MCP server is configured: server instances cannot be started on Windows yet (SRS FR-21.11).")
	}
	if _, err := ensureFile(filepath.Join(cfgDir, winServiceFile), []byte(winsvc.ServiceName+"\n"), 0o644); err != nil {
		return err
	}
	cfg, err := config.Load(res.cfgPath)
	if err != nil {
		return err
	}
	if in.noStart {
		in.step("skipped", "service start and health check (--no-start)")
	} else {
		if err := winsvc.StartService(); err != nil {
			return fmt.Errorf("start the service: %w", err)
		}
		in.step("present", "service "+winsvc.ServiceName+" running")
		// The service makes the CA certificate at its first start.
		deadline := time.Now().Add(in.healthWait)
		for _, err := os.Stat(filepath.Join(stateDir, "tls", "ca.crt")); err != nil && time.Now().Before(deadline); _, err = os.Stat(filepath.Join(stateDir, "tls", "ca.crt")) {
			time.Sleep(250 * time.Millisecond)
		}
		if err := in.verifyHealth(cfg); err != nil {
			return err
		}
	}
	fmt.Fprintf(in.out, `
This installation is not enforced (Windows machine mode, label "not
enforced, windows-machine"). smcpd runs as %s; its keys are DPAPI
blobs of that account. Administrators run smcpctl with the operator token
copy in the state directory. MCP servers are not yet contained on Windows.

Configuration: %s
Check health:  smcpctl health --config %s
Remove:        smcpctl uninstall --config %s   (as Administrator)
`, winsvc.ServiceAccount, res.cfgPath, winsvc.CommandLine(res.cfgPath), winsvc.CommandLine(res.cfgPath))
	return nil
}
