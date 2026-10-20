package main

import (
	"testing"

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
