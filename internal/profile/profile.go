// Package profile decides the deployment profile the Gateway runs under.
//
// Enforced profile: Linux (x86_64 or arm64) with rootless Podman, nftables,
// cgroup v2 and systemd, and a confining Launcher (E-16). Server instances
// run in sandboxes and every server class may be enabled.
//
// Standalone (unconfined) profile: any other host, including macOS arm64,
// or a host without a confining Launcher. Instances run as plain child
// processes, high-risk server classes are refused, health reports
// degraded with cause "unconfined", and the release label is
// "not enforced".
//
// Windows and WSL (SR-4-2): every installation on a Windows host, and every
// installation inside WSL, runs the Standalone profile with the label "not
// enforced" and reports its installation mode (windows-user,
// windows-machine or wsl2). Inside WSL this holds even when the enforced
// profile is configured and every Linux prerequisite is met, because any
// process of the Windows user can enter the distribution as root.
package profile

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Profile names.
const (
	Standalone = "standalone"
	Enforced   = "enforced"
)

// Installation modes on Windows hosts and in WSL (SR-4-2).
const (
	ModeWindowsUser    = "windows-user"
	ModeWindowsMachine = "windows-machine"
	ModeWSL2           = "wsl2"
)

// Host is what the enforced profile needs from the machine.
type Host struct {
	OS, Arch string
	Podman   bool
	Rootless bool
	Nftables bool
	CgroupV2 bool
	Systemd  bool
	// WSL is true inside a WSL distribution (SR-4-2).
	WSL bool
	// InstallMode is the Windows or WSL installation mode, or "" on other
	// hosts. DetectHost reports windows-user on Windows; the machine-mode
	// service sets windows-machine.
	InstallMode string
}

// Missing lists the enforced-profile prerequisites the host lacks.
func (h Host) Missing() []string {
	var out []string
	if h.OS != "linux" {
		out = append(out, "linux")
	}
	if h.WSL {
		out = append(out, "a host outside WSL (SR-4-2: a WSL installation is never enforced)")
	}
	if h.Arch != "amd64" && h.Arch != "arm64" {
		out = append(out, "amd64 or arm64")
	}
	for _, c := range []struct {
		ok   bool
		name string
	}{{h.Podman, "podman"}, {h.Rootless, "rootless (non-root user)"}, {h.Nftables, "nftables"}, {h.CgroupV2, "cgroup v2"}, {h.Systemd, "systemd"}} {
		if !c.ok {
			out = append(out, c.name)
		}
	}
	return out
}

// DetectHost inspects the running machine.
func DetectHost() Host {
	h := Host{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if h.OS == "windows" {
		h.InstallMode = ModeWindowsUser
	}
	if h.OS != "linux" {
		return h
	}
	rel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	if IsWSL(string(rel), os.Getenv("WSL_DISTRO_NAME")) {
		h.WSL, h.InstallMode = true, ModeWSL2
	}
	_, err := exec.LookPath("podman")
	h.Podman = err == nil
	h.Rootless = os.Geteuid() != 0
	_, err = exec.LookPath("nft")
	h.Nftables = err == nil
	_, err = os.Stat("/sys/fs/cgroup/cgroup.controllers")
	h.CgroupV2 = err == nil
	_, err = os.Stat("/run/systemd/system")
	h.Systemd = err == nil
	return h
}

// IsWSL reports whether a Linux host is a WSL distribution: the kernel
// release (/proc/sys/kernel/osrelease) contains "microsoft" or "WSL", or,
// as a second signal, WSL_DISTRO_NAME is set. The variable alone is not
// enough to rely on: it is set for processes started through wsl.exe, not
// for a systemd service inside the distribution (SR-4-2).
func IsWSL(osrelease, distroName string) bool {
	r := strings.ToLower(osrelease)
	return strings.Contains(r, "microsoft") || strings.Contains(r, "wsl") || distroName != ""
}

// Report is the resolved profile.
type Report struct {
	Mode     string // requested: auto, standalone or enforced
	Profile  string // Standalone or Enforced
	Confined bool
	Label    string   // release label: "enforced" or "not enforced"
	Reasons  []string // why the profile is standalone, when it is
	Launcher string
	Host     Host
	// InstallMode is the Windows or WSL installation mode (SR-4-2), or "".
	InstallMode string
}

// Resolve applies the configured mode to the host and launcher. Mode
// "enforced" fails when the enforced profile is unavailable, so a Gateway
// configured for enforcement never runs unconfined.
func Resolve(mode string, launcherName string, launcherConfined bool, host Host) (Report, error) {
	r := Report{Mode: mode, Launcher: launcherName, Host: host, InstallMode: host.InstallMode}
	missing := host.Missing()
	if !launcherConfined {
		missing = append(missing, "confining launcher (launcher "+launcherName+" is unconfined)")
	}
	switch {
	case mode == Standalone || (mode == "auto" && len(missing) > 0) || (mode == Enforced && host.WSL):
		r.Profile, r.Label = Standalone, "not enforced"
		if mode == Standalone {
			r.Reasons = []string{"standalone profile configured"}
		} else {
			r.Reasons = missing
		}
		r.Confined = false
	case len(missing) > 0:
		return r, fmt.Errorf("enforced profile requested but unavailable: missing %s", strings.Join(missing, ", "))
	default:
		r.Profile, r.Label, r.Confined = Enforced, "enforced", true
	}
	return r, nil
}

// Degraded reports the health cause of the profile, or "" when none.
func (r Report) Degraded() string {
	if r.Profile == Standalone {
		return "unconfined"
	}
	return ""
}
