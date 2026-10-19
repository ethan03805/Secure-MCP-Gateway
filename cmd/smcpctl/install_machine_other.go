//go:build !windows

package main

import "errors"

// windowsMachine is the Windows machine mode; elsewhere --machine fails.
func (in *installer) windowsMachine() error {
	return errors.New("--machine installs the Windows machine mode; on Linux use --profile enforced")
}

// machineConfigPath is the Windows machine-mode configuration, "" here.
func machineConfigPath() string { return "" }
