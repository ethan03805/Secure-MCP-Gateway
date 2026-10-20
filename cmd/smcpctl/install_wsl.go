package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
)

// The WSL2 installation mode (SRS FR-21.15, SR-4-2): the Linux build in a
// dedicated WSL2 distribution, reached from Windows agents over the
// distribution's forwarded loopback listener. The label stays "not
// enforced" with mode wsl2 (internal/profile detects WSL from the kernel
// release), because any process of the Windows user can run
// `wsl.exe -u root`.
const (
	// wslDistro is the name of the dedicated distribution.
	wslDistro = "smcp-gateway"
	// wslBase is the WSL distribution it is installed from.
	wslBase = "Ubuntu-24.04"
	// wslRepo is the repository whose install.sh and release are used.
	wslRepo = "ethan03805/Secure-MCP-Gateway"
)

// wslConf is /etc/wsl.conf of the distribution (FR-21.15): systemd as PID
// 1 for the smcpd service, and interop off, so that nothing inside the
// distribution can start a Windows program or find one on PATH.
func wslConf() string {
	return `# Written by smcpctl install --wsl (SRS FR-21.15). Interop stays off:
# backends inside this distribution cannot start Windows programs.
[boot]
systemd=true

[interop]
enabled=false
appendWindowsPath=false
`
}

// wslPath is the path of a Windows file as the distribution sees it
// through its automount (C:\x\y is /mnt/c/x/y).
func wslPath(win string) (string, error) {
	if len(win) < 3 || win[1] != ':' || (win[2] != '\\' && win[2] != '/') {
		return "", fmt.Errorf("%s is not an absolute path with a drive letter", win)
	}
	return "/mnt/" + strings.ToLower(win[:1]) + "/" + strings.ReplaceAll(win[3:], `\`, "/"), nil
}

// wslSteps are the commands of the WSL2 installation after the
// distribution exists, as fixed argument vectors (no Windows shell, SR-2-7):
// wsl.conf, a restart of the distribution so that systemd and the interop
// settings apply, the release's install.sh at tag (FR-13.5: minisign and
// SHA-256 checks), the Enforced prerequisites report (Section 1.5.1) and
// smcpctl install with the Enforced profile. confFile is wsl.conf written
// on the Windows side.
func wslSteps(confFile, tag string) ([][]string, error) {
	conf, err := wslPath(confFile)
	if err != nil {
		return nil, err
	}
	root := []string{"wsl.exe", "--distribution", wslDistro, "--user", "root", "--"}
	in := func(argv ...string) []string { return append(append([]string(nil), root...), argv...) }
	script := "https://raw.githubusercontent.com/" + wslRepo + "/" + tag + "/install.sh"
	return [][]string{
		in("cp", conf, "/etc/wsl.conf"),
		{"wsl.exe", "--terminate", wslDistro},
		in("apt-get", "update"),
		in("apt-get", "install", "-y", "curl", "minisign", "podman", "nftables", "uidmap"),
		in("curl", "-fsSLo", "/root/smcp-install.sh", script),
		in("sh", "/root/smcp-install.sh", "--version", tag, "--dir", "/usr/local/bin"),
		in("/usr/local/bin/smcpctl", "install", "--check", "--profile", "enforced"),
		in("/usr/local/bin/smcpctl", "install", "--profile", "enforced", "--bootstrap-token"),
	}, nil
}

// wslDefaultVersion is the release tag of this smcpctl, or "" for a
// development build, which has no release to install.
func wslDefaultVersion() string {
	v := backend.Version
	if v == "" || strings.Contains(v, "dev") {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// writeWSLTemp writes a file into a new temporary directory and returns
// its path and the removal of the directory.
func writeWSLTemp(name string, b []byte) (string, func(), error) {
	dir, err := os.MkdirTemp("", "smcp-wsl-")
	if err != nil {
		return "", nil, err
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return p, func() { os.RemoveAll(dir) }, nil
}

// windowsWSL installs the WSL2 mode: it creates the dedicated distribution
// when it is missing and runs wslSteps. tag is the release to install
// (default: this smcpctl's version).
func (in *installer) windowsWSL(tag string) error {
	if in.goos != "windows" {
		return errors.New("--wsl is the Windows WSL2 installation mode; on Linux run smcpctl install --profile enforced")
	}
	if tag == "" {
		return errors.New("--wsl needs the release to install inside the distribution: pass --wsl-version vX.Y.Z")
	}
	if !in.ok("wsl.exe", "--status") {
		return errors.New("WSL2 is not available on this host (it needs the Windows Subsystem for Linux and hardware virtualization); nothing was changed")
	}
	if in.ok("wsl.exe", "--distribution", wslDistro, "--user", "root", "--", "true") {
		in.step("present", "WSL2 distribution "+wslDistro)
	} else {
		if err := in.run("wsl.exe", "--install", "--distribution", wslBase, "--name", wslDistro, "--no-launch", "--web-download"); err != nil {
			return fmt.Errorf("create the distribution: %w", err)
		}
		in.step("created", "WSL2 distribution "+wslDistro+" (from "+wslBase+")")
	}
	write := in.wslTemp
	if write == nil {
		write = writeWSLTemp
	}
	conf, cleanup, err := write("wsl.conf", []byte(wslConf()))
	if err != nil {
		return err
	}
	defer cleanup()
	steps, err := wslSteps(conf, tag)
	if err != nil {
		return err
	}
	for _, argv := range steps {
		if err := in.run(argv...); err != nil {
			return err
		}
	}
	fmt.Fprintf(in.out, `
This installation is not enforced (WSL2 mode, label "not enforced, wsl2"):
any process of your Windows account can run wsl.exe -u root. smcpd runs as
a systemd service in the WSL2 distribution %s, with interop off.
Windows agents reach it at https://127.0.0.1:8443/mcp through WSL's
localhost forwarding. Redeem the bootstrap token printed above with
"wsl.exe -d %s -u root -- smcpctl admin redeem", then write the
credential file for smcp-stdio.exe with "smcpctl clients credentials".
`, wslDistro, wslDistro)
	return nil
}
