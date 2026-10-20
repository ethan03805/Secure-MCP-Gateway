//go:build windows

package main

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/harness"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

// errWinStopTimeout is returned when smcpd does not stop after its stop
// event was set.
var errWinStopTimeout = errors.New("smcpd did not stop after the stop request")

func defaultWinHooks() winHooks {
	return winHooks{
		launchSupported: pipeline.SubprocessSupported,
		version:         winsvc.HostVersion,
		userSID:         winsec.ProcessUserSID,
		secureDir:       winsec.SecureOwnerOnly,
		setRunValue:     winsvc.SetRunValue,
		startDetached: func(exe string, args []string, dir string) (int, error) {
			return winsvc.StartDetached(exe, args, dir, nil)
		},
	}
}

// winServiceDo starts or stops the per-user Gateway whose definition is u
// (FR-21.6, FR-21.7): stop sets the installation's stop event, which smcpd
// and its supervisor wait on, and waits for them to exit; start runs
// smcpd -supervise detached, as the logon start does.
func winServiceDo(u *unitFile, action string, binDir string) error {
	cfgPath := filepath.Join(filepath.Dir(u.path), "smcp.toml")
	switch action {
	case "stop":
		running, err := winsvc.SignalStop(cfgPath)
		if err != nil || !running {
			return err
		}
		for deadline := time.Now().Add(75 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			if running, _ := winsvc.SignalStop(cfgPath); !running {
				return nil
			}
		}
		return errWinStopTimeout
	default:
		smcpd := filepath.Join(binDir, "smcpd.exe")
		_, err := winsvc.StartDetached(smcpd, []string{"-supervise", "-config", cfgPath}, filepath.Dir(cfgPath), nil)
		return err
	}
}

// winRemoveUnit unregisters a per-user definition before its file goes.
func winRemoveUnit(u unitFile) {
	switch u.kind {
	case "win-task":
		_ = runQuiet("schtasks", "/delete", "/tn", winsvc.TaskName, "/f")
	case "win-run":
		_ = winsvc.DeleteRunValue()
	}
}

// platformDoctorFindings reports, on Windows, the installation mode and
// label (SR-4-2) and the state directory's DACL and key protection
// (FR-21.5, FR-21.10), which smcpd also checks at start.
func platformDoctorFindings(cfg *config.Config) []harness.Finding {
	out := []harness.Finding{{Kind: harness.KindInfo, Message: "Windows per-user mode (windows-user): not enforced; MCP servers run as your user (SR-4-2)"}}
	if cfg.State.Dir == "" {
		return out
	}
	if err := keys.CheckPrivate(cfg.State.Dir); err != nil {
		out = append(out, harness.Finding{Kind: "state-protection", Message: err.Error()})
	} else {
		out = append(out, harness.Finding{Kind: harness.KindInfo, Message: "state directory " + cfg.State.Dir + ": protected DACL (this user, SYSTEM and Administrators) and DPAPI-protected keys"})
	}
	switch {
	case winsvc.RunValueData() != "":
		out = append(out, harness.Finding{Kind: harness.KindWarning, Message: `smcpd starts at logon from HKCU\Software\Microsoft\Windows\CurrentVersion\Run (Windows refused the Task Scheduler task)`})
	case runQuiet("schtasks", "/query", "/tn", winsvc.TaskName) == nil:
		out = append(out, harness.Finding{Kind: harness.KindInfo, Message: "smcpd starts at logon from the Task Scheduler task " + winsvc.TaskName})
	}
	return out
}
