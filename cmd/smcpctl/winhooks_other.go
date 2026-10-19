//go:build !windows

package main

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/harness"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

// defaultWinHooks refuse off Windows; tests replace them to run the
// per-user Windows installation anywhere.
func defaultWinHooks() winHooks {
	return winHooks{
		launchSupported: pipeline.SubprocessSupported,
		version:         func() winsvc.Version { return winsvc.Version{} },
		userSID:         func() (string, error) { return "", winsvc.ErrNotWindows },
		secureDir:       func(string) error { return winsvc.ErrNotWindows },
		setRunValue:     func(string) error { return winsvc.ErrNotWindows },
		startDetached:   func(string, []string, string) (int, error) { return 0, winsvc.ErrNotWindows },
	}
}

func winServiceDo(*unitFile, string, string) error { return winsvc.ErrNotWindows }

func winRemoveUnit(unitFile) {}

// platformDoctorFindings has nothing to add off Windows.
func platformDoctorFindings(*config.Config) []harness.Finding { return nil }
