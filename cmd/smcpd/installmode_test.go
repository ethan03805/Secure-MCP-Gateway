package main

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestHostOverride: without an installation mode smcpd lets the app detect
// the host; the Windows machine-mode service passes windows-machine, which
// the release label then carries (SR-4-2).
func TestHostOverride(t *testing.T) {
	reqtest.Partial(t, "SR-4-2")
	if h := hostOverride(""); h != nil {
		t.Fatalf("hostOverride(\"\") = %+v, want nil (detect)", *h)
	}
	h := hostOverride(profile.ModeWindowsMachine)
	if h == nil || h.InstallMode != profile.ModeWindowsMachine {
		t.Fatalf("hostOverride(windows-machine) = %+v", h)
	}
	d := profile.DetectHost()
	if h.OS != d.OS || h.Arch != d.Arch {
		t.Fatalf("host %s/%s, detected %s/%s", h.OS, h.Arch, d.OS, d.Arch)
	}
	r, err := profile.Resolve("auto", "subprocess", false, *h)
	if err != nil {
		t.Fatal(err)
	}
	if r.InstallMode != profile.ModeWindowsMachine {
		t.Fatalf("report install mode %q", r.InstallMode)
	}
}

// TestMachineRuntime: the Windows machine-mode service runs packaged
// servers in their AppContainer placements (FR-21.13): sandbox "none"
// becomes "appcontainer" in the machine mode only, and an explicit sandbox
// is never replaced.
func TestMachineRuntime(t *testing.T) {
	reqtest.Partial(t, "FR-21.13")
	for _, tc := range []struct {
		mode, sandbox, want string
		changed             bool
	}{
		{profile.ModeWindowsMachine, "none", "appcontainer", true},
		{profile.ModeWindowsMachine, "appcontainer", "appcontainer", false},
		{profile.ModeWindowsUser, "none", "none", false},
		{"", "none", "none", false},
		{"", "podman", "podman", false},
	} {
		cfg := &config.Config{}
		cfg.Runtime.Sandbox = tc.sandbox
		if got := machineRuntime(cfg, tc.mode); got != tc.changed || cfg.Runtime.Sandbox != tc.want {
			t.Errorf("mode %q sandbox %q: changed %v sandbox %q, want %v %q", tc.mode, tc.sandbox, got, cfg.Runtime.Sandbox, tc.changed, tc.want)
		}
	}
}
