// Command smcpctl is the administrative CLI (FR-12.7 subset). Offline
// commands work on the configuration and state directory; control commands
// talk to the running Gateway's control API on the admin listener with the
// local operator token from the state directory.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

const usage = `usage: smcpctl <command> [flags]

Offline:
  bootstrap        create state, keys, TLS certificates, example config and policy
  config validate  validate the configuration and policy files
  journal verify   verify the evidence journal (hash chain, signatures, anchor)
  hash-password    print an Argon2id hash of a password (prompt or --password-file)

Control API (running Gateway):
  health           show the Gateway's health
  stop             emergency stop: refuse every tool call until resumed
  resume           leave emergency stop
  policy reload    validate and activate the policy file
  approvals        list pending approvals
  admin redeem     set the administrator password with the one-use bootstrap token

Every command takes --config <file> (default smcp.toml).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	sub := func(name string) bool { return len(args) > 1 && args[1] == name }
	var err error
	switch {
	case args[0] == "bootstrap":
		err = bootstrap(args[1:], stdout)
	case args[0] == "config" && sub("validate"):
		err = validate(args[2:], stdout)
	case args[0] == "journal" && sub("verify"):
		err = verify(args[2:], stdout)
	case args[0] == "hash-password":
		err = hashPassword(args[1:], stdout)
	case args[0] == "health":
		err = control(args[1:], stdout, "GET", "/admin/v1/health", nil)
	case args[0] == "stop":
		err = stopCmd(args[1:], stdout)
	case args[0] == "resume":
		err = control(args[1:], stdout, "POST", "/admin/v1/resume", map[string]any{})
	case args[0] == "policy" && sub("reload"):
		err = control(args[2:], stdout, "POST", "/admin/v1/policy/reload", map[string]any{})
	case args[0] == "approvals":
		err = control(args[1:], stdout, "GET", "/admin/v1/approvals", nil)
	case args[0] == "admin" && sub("redeem"):
		err = redeem(args[2:], stdout)
	case args[0] == "help" || args[0] == "-h" || args[0] == "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "smcpctl:", err)
		return 1
	}
	return 0
}

func validate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	snap, err := policy.Load(cfg.Policy.File)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "configuration OK: %d principals, %d clients, %d servers, %d approvers; policy revision %s\n",
		len(cfg.Principals), len(cfg.Clients), len(cfg.Servers), len(cfg.Approvers), snap.Revision)
	return nil
}

func verify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("journal verify", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	dir := fs.String("dir", "", "journal directory (default <state>/journal)")
	anchor := fs.String("anchor", "", "anchor file (default <journal dir>.anchor)")
	strict := fs.Bool("strict", false, "treat findings (recovered segments, truncated tail) as failures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	pub, err := keys.LoadEvidencePublicKey(cfg.State.Dir)
	if err != nil {
		return err
	}
	if *dir == "" {
		*dir = filepath.Join(cfg.State.Dir, "journal")
	}
	rep, err := audit.VerifyWith(*dir, pub, audit.VerifyOptions{AnchorPath: *anchor})
	if err != nil {
		return fmt.Errorf("journal verification FAILED: %w", err)
	}
	fmt.Fprintf(out, "journal OK: %d segments, %d events", rep.Segments, rep.Events)
	if rep.AnchorSegment > 0 {
		fmt.Fprintf(out, ", anchored at segment %d", rep.AnchorSegment)
	}
	if rep.Open != "" {
		fmt.Fprintf(out, " (%s is still open)", rep.Open)
	}
	fmt.Fprintln(out)
	findings := rep.Findings()
	for _, f := range findings {
		fmt.Fprintln(out, "FINDING:", f)
	}
	if *strict && len(findings) > 0 {
		return fmt.Errorf("%d findings", len(findings))
	}
	return nil
}

// readSecret reads a secret from file ("-" is standard input) or, when file
// is empty, from an interactive prompt with confirmation. Secrets are never
// taken from the command line or the environment.
func readSecret(file, prompt string, confirm bool) (string, error) {
	if file != "" {
		var b []byte
		var err error
		if file == "-" {
			b, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
		} else {
			b, err = os.ReadFile(file)
		}
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal for the password prompt; pass a password file")
	}
	fmt.Fprint(os.Stderr, prompt+": ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("the two entries differ")
		}
	}
	return string(a), nil
}

func hashPassword(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	file := fs.String("password-file", "", "read the password from this file (- for standard input) instead of a prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw, err := readSecret(*file, "Password", true)
	if err != nil {
		return err
	}
	if pw == "" {
		return errors.New("empty password")
	}
	h, err := keys.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, h)
	return nil
}
