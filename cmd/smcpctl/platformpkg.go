package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/harness"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

// Platform packages (E-35, SRS FR-20.17 to FR-20.22). The .deb and .rpm
// install the binaries in /usr/bin and the marker /usr/lib/smcp/package-format;
// the macOS .pkg installs them in /usr/local/lib/smcp, with the marker
// beside them and links in /usr/local/bin. The marker holds the package
// format (deb, rpm or pkg). The packages create no configuration, state,
// keys, unit or account (FR-20.21): `smcpctl install` does that, from the
// packaged binaries, exactly as from an archive.
const packageMarker = "package-format"

// packageFormat returns the platform package format that installed the
// binaries in binDir (deb, rpm or pkg), or "" when they did not come from a
// platform package (install.sh, Homebrew, a source build).
func packageFormat(binDir string) string {
	d, err := filepath.EvalSymlinks(binDir)
	if err != nil {
		d = binDir
	}
	for _, p := range []string{filepath.Join(d, packageMarker), filepath.Join(d, "..", "lib", "smcp", packageMarker)} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		switch f := strings.TrimSpace(string(b)); f {
		case "deb", "rpm", "pkg", "msi":
			return f
		}
	}
	return ""
}

// packageRemoveHint is the command that removes the files of a package.
func packageRemoveHint(format string) string {
	switch format {
	case "deb":
		return "sudo apt remove smcp"
	case "rpm":
		return "sudo dnf remove smcp"
	case "pkg":
		return "the commands in docs/install.md, \"Remove the macOS package\""
	case "msi":
		return "Settings > Apps > Installed apps > Secure MCP Gateway > Uninstall, or msiexec /x with the .msi"
	}
	return ""
}

// errPackaged refuses an operation on binaries a platform package owns.
func errPackaged(binDir, format, what string) error {
	return fmt.Errorf("the binaries in %s were installed by the smcp %s package; %s them with the package manager, not smcpctl (remove: %s)", binDir, format, what, packageRemoveHint(format))
}

// packageRemoval is `smcpctl uninstall --package-removal`, which the
// pre-removal script of the .deb and .rpm runs as root when the package is
// removed (not upgraded). By owner decision it stops and removes only the
// system-wide smcpd service that `smcpctl install --profile enforced`
// created (FR-20.22): smcpd.service and smcp-nftables.service. It keeps the
// configuration, state, evidence journal, keys and backups, and every other
// host object, and it never fails the package removal: a problem is
// printed, not returned. On Windows the .msi packages run it when they are
// removed (not upgraded), for the machine-mode service (FR-21.6):
// windowsPackageRemoval.
func packageRemoval(out io.Writer, goos string, run func(argv ...string) error) error {
	if goos == "windows" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(out, "package removal: cannot locate smcpctl: %v\n", err)
			return nil
		}
		return windowsPackageRemoval(out, filepath.Dir(exe), winsvc.ServiceImage, func() error {
			if err := winsvc.StopService(75 * time.Second); err != nil {
				return err
			}
			return winsvc.DeleteService()
		})
	}
	if goos != "linux" {
		fmt.Fprintf(out, "package removal: no system service on %s\n", goos)
		return nil
	}
	removed := false
	for _, unit := range []string{systemdUnit, nftUnit} {
		p := filepath.Join(hostRoot, "/etc/systemd/system", unit)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := run("systemctl", "disable", "--now", unit); err != nil {
			fmt.Fprintf(out, "systemctl disable --now %s: %v\n", unit, err)
		} else {
			fmt.Fprintf(out, "stopped and disabled %s\n", unit)
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(out, "unit %s: %v\n", p, err)
			continue
		}
		fmt.Fprintf(out, "removed %s\n", p)
		removed = true
	}
	if removed {
		_ = run("systemctl", "daemon-reload")
	} else {
		fmt.Fprintln(out, "package removal: no system smcpd service installed")
	}
	fmt.Fprintln(out, "kept: configuration, state, evidence journal, evidence keys, backups, the nftables table, LSM profiles and service identities")
	fmt.Fprintln(out, "per-user services: run `smcpctl uninstall` as each user before removing the package; to delete everything: `smcpctl uninstall --purge`")
	return nil
}

// windowsPackageRemoval is `smcpctl uninstall --package-removal` run by
// the smcp and smcp-desktop .msi packages, as the system account, before
// they remove their files (FR-20.22). It stops and removes the
// machine-mode service smcpd when the service runs this package's own
// smcpd (the smcp .msi's directory) or a copy that no package owns (the
// copy `smcpctl install --machine` made from the smcp-desktop package);
// a service that runs the smcpd of another installed smcp package stays.
// The per-user task, configuration, state, journal, keys and backups
// stay, and a problem is printed, never returned.
func windowsPackageRemoval(out io.Writer, pkgDir string, image func() (string, bool, error), remove func() error) error {
	img, installed, err := image()
	switch {
	case err != nil:
		fmt.Fprintf(out, "package removal: cannot read the smcpd service: %v\n", err)
	case !installed:
		fmt.Fprintln(out, "package removal: no smcpd service installed")
	default:
		dir := filepath.Dir(img)
		if !strings.EqualFold(filepath.Clean(dir), filepath.Clean(pkgDir)) && packageFormat(dir) != "" {
			fmt.Fprintf(out, "kept: the smcpd service, which runs %s of another smcp package\n", img)
			break
		}
		if err := remove(); err != nil {
			fmt.Fprintf(out, "package removal: the smcpd service (%s): %v\n", img, err)
		} else {
			fmt.Fprintf(out, "stopped and removed the smcpd service (%s)\n", img)
		}
	}
	fmt.Fprintln(out, "kept: configuration, state, evidence journal, evidence keys, backups and the per-user task")
	fmt.Fprintln(out, "per-user installations: run `smcpctl uninstall` as each user before removing the package; to delete everything: `smcpctl uninstall --purge`")
	return nil
}

// binaryWritableFindings is the SR-4.11-2 check of `smcpctl doctor`: a
// Gateway binary, or the directory holding it, that the user running doctor
// can write. An agent runs as that user, so it could replace the Gateway.
// The platform packages install root-owned files; install.sh into the
// user's own directory, a .dmg copy and an AppImage leave them writable.
// In the Enforced profile the finding fails doctor; in the Standalone
// profile, where the agent already shares the Gateway's identity, it is a
// warning.
func binaryWritableFindings(exe string, euid int, enforced bool, writable func(string) bool) []harness.Finding {
	if euid == 0 {
		return []harness.Finding{{Kind: harness.KindInfo, Message: "doctor runs as root, which can write every file; run it as the user that runs the agents to check that the Gateway binaries are not writable (SR-4.11-2)"}}
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	var paths []string
	if writable(dir) {
		paths = append(paths, dir)
	}
	for _, name := range releaseBinaries {
		p := filepath.Join(dir, exeName(runtime.GOOS, name))
		if _, err := os.Stat(p); err == nil && writable(p) {
			paths = append(paths, p)
		}
	}
	// Inside an AppImage the binaries are on a read-only mount, but the
	// AppImage file that holds them is the user's own (FR-20.19).
	if img := appImageFile(exe, os.Getenv("APPIMAGE"), os.Getenv("APPDIR")); img != "" && writable(img) {
		paths = append(paths, img)
	}
	if len(paths) == 0 {
		return []harness.Finding{{Kind: harness.KindInfo, Path: dir, Message: "the Gateway binaries and their directory are not writable by this user (SR-4.11-2)"}}
	}
	kind, prefix := harness.KindBinaryWritable, ""
	if !enforced {
		kind, prefix = harness.KindWarning, harness.KindBinaryWritable+": "
	}
	fix := "install from the .pkg, .deb or .rpm package, or make it root-owned"
	if runtime.GOOS == "windows" {
		fix = "install from the .msi package, or let only Administrators write it"
	}
	var out []harness.Finding
	for _, p := range paths {
		out = append(out, harness.Finding{Kind: kind, Path: p,
			Message: prefix + "this user, who runs the agents, can write this Gateway binary, directory or AppImage and so replace the Gateway; " + fix + " (SR-4.11-2)"})
	}
	return out
}

// appImageFile returns the AppImage that holds exe: the AppImage runtime
// mounts the image at APPDIR and names the image file in APPIMAGE, and
// passes both to the processes it starts. It returns "" when exe is not
// below APPDIR.
func appImageFile(exe, appImage, appDir string) string {
	if appImage == "" || appDir == "" || !filepath.IsAbs(appImage) {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(appDir), exe)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return appImage
}

// doctorBinaryFindings runs binaryWritableFindings for this smcpctl.
var doctorBinaryFindings = func(enforced bool) []harness.Finding {
	exe, err := os.Executable()
	if err != nil {
		return []harness.Finding{{Kind: harness.KindWarning, Message: "cannot locate the smcpctl executable: " + err.Error()}}
	}
	return binaryWritableFindings(exe, os.Geteuid(), enforced, canWritePath)
}
