//go:build windows

package pipeline

import "errors"

// ErrLaunchUnsupported is returned by SubprocessLauncher.Launch on Windows.
// Starting a backend there safely needs the FR-21.11 launch rules
// (CreateProcess quoting, refusal of cmd.exe, PowerShell and batch files,
// SR-4.8-2) and the FR-21.12 Job Object that keeps no backend alive after
// the Gateway. Until they exist the launcher refuses rather than start an
// uncontained process.
var ErrLaunchUnsupported = errors.New("server instances cannot be started on Windows yet: the FR-21.11 launch rules and FR-21.12 Job Object containment are not implemented; refusing to start an uncontained process")

func subprocessSupported() error { return ErrLaunchUnsupported }
