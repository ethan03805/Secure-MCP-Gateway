package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// nftTable is the nftables table the egress broker (E-18) installs.
const nftTable = "inet smcp"

// serviceIdentities are the CP-46 Enforced-profile accounts.
var serviceIdentities = []string{"smcp-core", "smcp-evidence", "smcp-keys", "smcp-vault", "smcp-data", "smcp-console", "smcp-srv"}

// uninstallCmd is `smcpctl uninstall [--purge]` (FR-13.11, FR-13.12).
func uninstallCmd(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "also delete configuration, state, keys, the journal and the service identities (asks for the installation ID)")
	binDir := fs.String("bin-dir", "", "directory of the installed binaries (default: the directory of this smcpctl)")
	stopCmd := fs.String("stop-cmd", "", "shell command that stops the Gateway (default: the installed launchd or systemd unit)")
	cfg, cfgPath, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if *binDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		*binDir = filepath.Dir(exe)
	}
	cfgAbs, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	jdir := filepath.Join(cfg.State.Dir, "journal")

	// The purge confirmation comes first, so that a refusal changes nothing.
	if *purge {
		id, err := keys.EnsureInstallationID(cfg.State.Dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Purging deletes the configuration, state, keys and the evidence journal of installation %s.\nType the installation ID to continue: ", id)
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(line) != id {
			return errors.New("installation ID does not match; nothing was removed")
		}
	}

	// 1. Stop the service.
	svc := service{stopCmd: *stopCmd}
	if daemonUp(cfg) {
		if err := svc.stop(); err != nil {
			return fmt.Errorf("stop the Gateway first: %w", err)
		}
		for deadline := time.Now().Add(30 * time.Second); daemonUp(cfg); time.Sleep(200 * time.Millisecond) {
			if time.Now().After(deadline) {
				return errors.New("the Gateway is still running; stop it and run uninstall again")
			}
		}
	}
	fmt.Fprintln(out, "service: stopped")

	// 2. Units, nftables table, LSM profiles, binaries.
	for _, u := range unitFiles() {
		if !u.exists {
			continue
		}
		err := os.Remove(u.path)
		if errors.Is(err, os.ErrPermission) && hostRoot == "" {
			err = runQuiet(asRoot("rm", "-f", u.path)...) // system units belong to root
		}
		if err != nil {
			fmt.Fprintf(out, "unit %s: %v\n", u.path, err)
			continue
		}
		fmt.Fprintf(out, "removed %s\n", u.path)
		if strings.HasPrefix(u.kind, "systemd") && hostRoot == "" {
			argv := asRoot("systemctl", "daemon-reload")
			if u.kind == "systemd-user" {
				argv = []string{"systemctl", "--user", "daemon-reload"}
			}
			_ = runQuiet(argv...)
		}
	}
	if hostRoot == "" {
		fmt.Fprintln(out, removeNftTable())
		for _, line := range removeLSMProfiles() {
			fmt.Fprintln(out, line)
		}
	}
	for _, name := range releaseBinaries {
		for _, p := range []string{filepath.Join(*binDir, name), filepath.Join(*binDir, name+".prev")} {
			if err := os.Remove(p); err == nil {
				fmt.Fprintf(out, "removed %s\n", p)
			} else if !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(out, "%s: %v\n", p, err)
			}
		}
	}

	if !*purge {
		fmt.Fprintf(out, "kept: evidence journal %s, evidence public keys in %s, backups in %s, configuration %s and state %s\n",
			jdir, filepath.Join(cfg.State.Dir, "keys"), cfg.Backup.Dir, cfgAbs, cfg.State.Dir)
		fmt.Fprintf(out, "verify the kept journal later with: smcpctl journal verify --dir %s --key %s\n", jdir, filepath.Join(cfg.State.Dir, keys.EvidenceGenesisFile))
		return nil
	}

	// 3. Purge.
	if name, sum, err := audit.LastSegment(jdir); err == nil && name != "" {
		fmt.Fprintf(out, "last journal segment %s sha256 %s\n", name, sum)
	} else {
		fmt.Fprintln(out, "no journal segment found")
	}
	for _, p := range []string{cfg.Policy.File, cfgAbs} {
		if err := os.Remove(p); err == nil {
			fmt.Fprintf(out, "removed %s\n", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.RemoveAll(cfg.State.Dir); err != nil {
		return err
	}
	fmt.Fprintf(out, "removed %s\n", cfg.State.Dir)
	// The diagnostic log may live outside the state directory; only its
	// own files are removed, never the directory it sits in.
	logs, _ := filepath.Glob(cfg.Log.File + "*")
	for _, p := range logs {
		if p == cfg.Log.File || strings.TrimLeft(strings.TrimPrefix(p, cfg.Log.File+"."), "0123456789") == "" {
			if err := os.Remove(p); err == nil {
				fmt.Fprintf(out, "removed %s\n", p)
			}
		}
	}
	if hostRoot == "" {
		for _, line := range removeIdentities() {
			fmt.Fprintln(out, line)
		}
	}
	fmt.Fprintf(out, "kept: backups in %s (delete them separately)\n", cfg.Backup.Dir)
	return nil
}

func runQuiet(argv ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, argv[0], argv[1:]...).Run()
}

// asRoot prefixes sudo -n when not running as root.
func asRoot(argv ...string) []string {
	if os.Geteuid() == 0 {
		return argv
	}
	return append([]string{"sudo", "-n"}, argv...)
}

func removeNftTable() string {
	if runtime.GOOS != "linux" {
		return "nftables: not used on " + runtime.GOOS
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return "nftables: nft not installed; nothing to remove"
	}
	parts := strings.Fields(nftTable)
	if runQuiet(asRoot("nft", "list", "table", parts[0], parts[1])...) != nil {
		return "nftables: table " + nftTable + " not present"
	}
	if err := runQuiet(asRoot("nft", "delete", "table", parts[0], parts[1])...); err != nil {
		return "nftables: could not delete table " + nftTable + ": " + err.Error()
	}
	return "nftables: removed table " + nftTable
}

func removeLSMProfiles() []string {
	if runtime.GOOS != "linux" {
		return []string{"LSM profiles: not used on " + runtime.GOOS}
	}
	matches, _ := filepath.Glob("/etc/apparmor.d/smcp-*")
	if len(matches) == 0 {
		return []string{"LSM profiles: none installed"}
	}
	var out []string
	for _, m := range matches {
		_ = runQuiet(asRoot("apparmor_parser", "-R", m)...)
		if err := runQuiet(asRoot("rm", "-f", m)...); err != nil {
			out = append(out, "LSM profile "+m+": "+err.Error())
		} else {
			out = append(out, "removed LSM profile "+m)
		}
	}
	return out
}

func removeIdentities() []string {
	if runtime.GOOS != "linux" {
		return []string{"service identities: none on " + runtime.GOOS + " (Standalone profile runs as the user)"}
	}
	var out []string
	for _, name := range serviceIdentities {
		if _, err := user.Lookup(name); err != nil {
			continue
		}
		if err := runQuiet(asRoot("userdel", name)...); err != nil {
			out = append(out, "service identity "+name+": "+err.Error())
		} else {
			out = append(out, "removed service identity "+name)
		}
	}
	if len(out) == 0 {
		out = append(out, "service identities: none present")
	}
	return out
}
