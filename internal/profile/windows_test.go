package profile

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsAndWSLProfiles: a Windows host and a WSL distribution run the
// Standalone profile with the label "not enforced" and their installation
// mode, never health "healthy"; inside WSL even an enforced configuration
// on a host with every Linux prerequisite does (SR-4-2). Partial: the label
// in smcpctl health and version, the console banner and the startup log
// entry are tested where they are shown, and the machine and WSL2 modes are
// not installable yet.
func TestWindowsAndWSLProfiles(t *testing.T) {
	reqtest.Partial(t, "SR-4-2")
	wsl := Host{OS: "linux", Arch: "amd64", Podman: true, Rootless: true, Nftables: true, CgroupV2: true, Systemd: true, WSL: true, InstallMode: ModeWSL2}
	for _, mode := range []string{"auto", Enforced, Standalone} {
		r, err := Resolve(mode, "podman", true, wsl)
		if err != nil || r.Profile != Standalone || r.Label != "not enforced" || r.Degraded() != "unconfined" || r.InstallMode != ModeWSL2 || r.Confined {
			t.Fatalf("WSL %s: %+v %v", mode, r, err)
		}
		if mode != Standalone && !strings.Contains(strings.Join(r.Reasons, ","), "SR-4-2") {
			t.Fatalf("WSL %s: reasons %v", mode, r.Reasons)
		}
	}
	for _, im := range []string{ModeWindowsUser, ModeWindowsMachine} {
		win := Host{OS: "windows", Arch: "amd64", InstallMode: im}
		r, err := Resolve("auto", "subprocess", false, win)
		if err != nil || r.Profile != Standalone || r.Label != "not enforced" || r.Degraded() == "" || r.InstallMode != im {
			t.Fatalf("%s: %+v %v", im, r, err)
		}
		if _, err := Resolve(Enforced, "subprocess", false, win); err == nil {
			t.Fatalf("%s: enforced configuration accepted", im)
		}
	}
	if r, _ := Resolve("auto", "subprocess", false, Host{OS: "darwin", Arch: "arm64"}); r.InstallMode != "" {
		t.Fatalf("macOS install mode %q", r.InstallMode)
	}
	if h := DetectHost(); (h.OS == "windows") != (h.InstallMode == ModeWindowsUser) && !h.WSL {
		t.Fatalf("detected %+v", h)
	}
}

// TestPartiallyConfinedCause: the machine mode with every backend in an
// AppContainer reports partially_confined; one uncontained backend, or
// another mode, reports unconfined (FR-21.13).
func TestPartiallyConfinedCause(t *testing.T) {
	reqtest.Partial(t, "FR-21.13")
	machine, _ := Resolve("auto", "subprocess", false, Host{OS: "windows", Arch: "amd64", InstallMode: ModeWindowsMachine})
	user, _ := Resolve("auto", "subprocess", false, Host{OS: "windows", Arch: "amd64", InstallMode: ModeWindowsUser})
	enforced, _ := Resolve("auto", "podman", true, Host{OS: "linux", Arch: "amd64", Podman: true, Rootless: true, Nftables: true, CgroupV2: true, Systemd: true})
	for _, c := range []struct {
		r    Report
		all  bool
		want string
	}{
		{machine, true, CausePartiallyConfined}, {machine, false, CauseUnconfined},
		{user, true, CauseUnconfined}, {enforced, true, ""}, {enforced, false, ""},
	} {
		if got := c.r.Cause(c.all); got != c.want {
			t.Errorf("%s contained=%v: %q, want %q", c.r.InstallMode, c.all, got, c.want)
		}
	}
}

func TestIsWSL(t *testing.T) {
	reqtest.Partial(t, "SR-4-2")
	for _, c := range []struct {
		rel, env string
		want     bool
	}{
		{"6.18.3-microsoft-standard-WSL2\n", "", true},
		{"5.15.153.1-microsoft-standard-WSL2", "", true},
		{"4.4.0-19041-Microsoft", "", true},
		{"6.8.0-45-generic", "Ubuntu", true},
		{"6.8.0-45-generic", "", false},
		{"", "", false},
	} {
		if got := IsWSL(c.rel, c.env); got != c.want {
			t.Errorf("IsWSL(%q, %q) = %v", c.rel, c.env, got)
		}
	}
}
