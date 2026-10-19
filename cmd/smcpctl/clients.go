package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/harness"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

const clientsUsage = `usage: smcpctl clients <command> [flags]

Remote Access client registrations (running Gateway, Administrator):
  list [--status pending|approved|denied|revoked]
  show <client-id>
  approve <client-id> [--principal ID] [--comment TEXT]
  deny <client-id> [--comment TEXT]
  revoke <client-id> [--comment TEXT]

Harness configuration (this user's client files):
  detect [--json]   supported clients found on this computer and their setup state
  setup <client> [--dry-run [--json]] [--stdio] [--helper] [--no-lockdown] [--system-trust] [--remove]
  credentials --client-id ID --secret-file FILE [--template T] [--out FILE]
  (smcpctl connect <client> [flags] is an alias of setup)

Clients: ` + "claude-code, codex, gemini-cli, goose, grok-build, hermes, opencode" + `
`

func clientsCmd(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(clientsUsage))
	}
	switch args[0] {
	case "list":
		return clientsList(args[1:], out)
	case "show":
		return clientsOne(args[1:], out, "show")
	case "approve", "deny", "revoke":
		return clientsOne(args[1:], out, args[0])
	case "setup":
		return clientSetup(args[1:], out)
	case "detect":
		return clientsDetect(args[1:], out)
	case "credentials":
		return clientCredentials(args[1:], out)
	}
	return errors.New(strings.TrimSpace(clientsUsage))
}

// splitArgs separates leading positional arguments from flags so that
// `approve <id> --principal p` works with the flag package.
func splitArgs(args []string) (pos, flags []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return pos, args[i:]
		}
		pos = append(pos, a)
	}
	return pos, nil
}

func clientsList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("clients list", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	status := fs.String("status", "", "filter by status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	path := "/api/v1/clients"
	if *status != "" {
		path += "?status=" + url.QueryEscape(*status)
	}
	res, _, err := c.do("GET", path, nil)
	if err != nil {
		return err
	}
	list, _ := res["clients"].([]any)
	if len(list) == 0 {
		fmt.Fprintln(out, "no remote clients")
		return nil
	}
	for _, x := range list {
		m, _ := x.(map[string]any)
		fmt.Fprintf(out, "%-48v %-9v %-15v %-10v %v\n", m["client_id"], m["status"], m["registration"], m["principal"], m["client_name"])
	}
	return nil
}

func clientsOne(args []string, out io.Writer, action string) error {
	pos, rest := splitArgs(args)
	fs := flag.NewFlagSet("clients "+action, flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	principal := fs.String("principal", "", "principal to bind the client to (approve)")
	comment := fs.String("comment", "", "comment recorded with the decision")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: smcpctl clients %s <client-id>", action)
	}
	id := url.PathEscape(pos[0])
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	var res map[string]any
	if action == "show" {
		res, _, err = c.do("GET", "/api/v1/clients/"+id, nil)
	} else {
		res, _, err = c.do("POST", "/api/v1/clients/"+id+"/"+action, map[string]any{"principal": *principal, "comment": *comment})
	}
	if err != nil {
		return err
	}
	printJSON(out, res)
	return nil
}

// harnessEnv describes the configured Gateway for the harness package.
func harnessEnv(cfg *config.Config) (harness.Env, error) {
	origins := []string{originOf(cfg.Listener.PublicURL), "https://" + cfg.Listener.Address}
	if cfg.Remote.PublicURL != "" {
		origins = append(origins, cfg.Remote.PublicURL)
	}
	if b, err := os.ReadFile(filepath.Join(cfg.State.Dir, "remote", "state.json")); err == nil {
		var st struct {
			PublicURL string `json:"public_url"`
		}
		if json.Unmarshal(b, &st) == nil && st.PublicURL != "" {
			origins = append(origins, st.PublicURL)
		}
	}
	gw := harness.Gateway{MCPURL: cfg.ResourceURI(), CAFile: filepath.Join(cfg.State.Dir, keys.CACertFile), Credentials: adapter.DefaultPath(),
		Origins: origins, Standalone: cfg.Profile.Mode == "standalone" || runtime.GOOS != "linux"}
	e, err := harness.NewEnv(gw)
	if err != nil {
		return e, err
	}
	e.Paths = []string{cfg.State.Dir}
	// The configuration directory is protected unless it is the user's
	// home or contains the current project, where a deny rule would block
	// ordinary work.
	if rel, err := filepath.Rel(cfg.Dir, e.CWD); cfg.Dir != e.Home && (err != nil || strings.HasPrefix(rel, "..")) {
		e.Paths = append(e.Paths, cfg.Dir)
	}
	for _, p := range []string{"/etc/smcp", "/var/lib/smcp", "/var/log/smcp", filepath.Join(e.Home, "Library", "Application Support", "smcp-gateway"),
		filepath.Join(e.Home, "Library", "Logs", "smcp-gateway"), filepath.Join(e.Home, ".local", "state", "smcp-gateway"), filepath.Join(e.Home, ".config", "smcp-gateway")} {
		if _, err := os.Stat(p); err == nil {
			e.Paths = append(e.Paths, p)
		}
	}
	if root := os.Getenv("SMCP_HARNESS_ROOT"); root != "" { // tests: managed paths under a temporary root
		e.Root = root
	}
	return e, nil
}

func originOf(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return u
	}
	return pu.Scheme + "://" + pu.Host
}

func clientSetup(args []string, out io.Writer) error {
	pos, rest := splitArgs(args)
	fs := flag.NewFlagSet("clients setup", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	dry := fs.Bool("dry-run", false, "show the changes without writing anything")
	stdio := fs.Bool("stdio", false, "connect through smcp-stdio even where the client supports HTTP")
	helper := fs.Bool("helper", false, "use smcp-session as a header helper (Claude Code) or HTTP instead of smcp-stdio (others)")
	noLock := fs.Bool("no-lockdown", false, "do not apply the lockdown profile")
	systemTrust := fs.Bool("system-trust", false, "also add the Gateway CA to the operating-system trust store")
	remove := fs.Bool("remove", false, "restore the files changed by a previous setup (and its lockdown)")
	asJSON := fs.Bool("json", false, "with --dry-run: print the changes as JSON (the desktop client setup reads it)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *asJSON && !*dry {
		return errors.New("--json needs --dry-run")
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl clients setup <client> [flags]\nclients: " + strings.Join(harness.IDs(), ", "))
	}
	cl, ok := harness.Lookup(pos[0])
	if !ok {
		return fmt.Errorf("unknown client %q; known: %s", pos[0], strings.Join(harness.IDs(), ", "))
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	e, err := harnessEnv(cfg)
	if err != nil {
		return err
	}
	if *remove {
		var errs []error
		for _, kind := range []string{"lockdown", "setup"} {
			mp := harness.ManifestPath(e.Home, cl.ID, kind)
			if _, err := os.Stat(mp); err != nil {
				continue
			}
			m, err := harness.Remove(mp)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			fmt.Fprintf(out, "%s %s removed: %d files restored\n", cl.ID, kind, len(m.Files))
		}
		return errors.Join(errs...)
	}
	plan, err := cl.Setup(e, harness.Options{Stdio: *stdio, Helper: *helper})
	if err != nil {
		return err
	}
	if *systemTrust {
		plan.Commands = append(plan.Commands, harness.SystemTrustCommands(e.OS, e.Home, e.CAFile)...)
	}
	var lock harness.Plan
	if !*noLock {
		if lock, err = cl.Lockdown(e); err != nil {
			return err
		}
	}
	if *dry && *asJSON {
		r := dryRunJSON{Client: cl.ID, Name: cl.Name, Setup: planToJSON(plan)}
		if !*noLock {
			l := planToJSON(lock)
			r.Lockdown = &l
		}
		printJSON(out, r)
		return nil
	}
	if *dry {
		fmt.Fprint(out, "dry run: nothing is written\n"+harness.Describe(plan))
		if !*noLock {
			fmt.Fprint(out, "lockdown "+harness.Describe(lock))
		}
		return nil
	}
	if err := applyPlan(out, plan, e.Home, "setup"); err != nil {
		return err
	}
	for _, cmd := range plan.Commands {
		c := exec.Command(cmd[0], cmd[1:]...)
		c.Stdout, c.Stderr, c.Stdin = out, os.Stderr, os.Stdin
		if err := c.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(cmd, " "), err)
		}
	}
	if !*noLock {
		if err := applyPlan(out, lock, e.Home, "lockdown"); err != nil {
			return fmt.Errorf("lockdown: %w (connection settings were written; run with --no-lockdown or as the user who can write the managed path)", err)
		}
	}
	fmt.Fprintf(out, "Next: run `smcpctl doctor --client %s` and resolve every finding.\n", cl.ID)
	return nil
}

func applyPlan(out io.Writer, p harness.Plan, home, kind string) error {
	if len(p.Changes) > 0 {
		m, err := harness.Apply(p, harness.ManifestPath(home, p.Client, kind), kind, time.Now())
		if err != nil {
			return err
		}
		for _, f := range m.Files {
			if f.Existed {
				fmt.Fprintf(out, "%s %s: wrote %s (backup %s)\n", p.Client, kind, f.Path, f.Backup)
			} else {
				fmt.Fprintf(out, "%s %s: created %s\n", p.Client, kind, f.Path)
			}
		}
	}
	for _, n := range p.Notes {
		fmt.Fprintf(out, "%s %s note: %s\n", p.Client, kind, n)
	}
	return nil
}

// clientCredentials writes the CP-43 credential file for smcp-stdio and
// smcp-session.
func clientCredentials(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("clients credentials", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	id := fs.String("client-id", "", "confidential [[client]] ID")
	secretFile := fs.String("secret-file", "", "file holding the client secret (- for standard input)")
	template := fs.String("template", "", "session template (default: the principal's default)")
	outPath := fs.String("out", adapter.DefaultPath(), "credential file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("--client-id is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.FindClient(*id) == nil {
		return fmt.Errorf("client %q is not in the configuration", *id)
	}
	secret, err := readSecret(*secretFile, "Client secret", false)
	if err != nil {
		return err
	}
	c, err := adapter.LoadOrNew(*outPath)
	if err != nil {
		return err
	}
	c.Gateway = adapter.GatewaySection{URL: cfg.ResourceURI(), CAFile: filepath.Join(cfg.State.Dir, keys.CACertFile)}
	c.Client = adapter.ClientSection{ID: *id, Secret: secret, Template: *template}
	c.Session = adapter.SessionSection{}
	if err := c.Save(); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (mode 0600)\n", c.Path())
	return nil
}

// detectedClient is one Appendix K client as `clients detect` reports it.
type detectedClient struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	// Connected: a setup by smcpctl is recorded (its manifest exists), so
	// --remove restores the client's files.
	Connected bool `json:"connected"`
	// Lockdown: a lockdown profile by smcpctl is recorded.
	Lockdown bool `json:"lockdown"`
	// LockdownAvailable: the client offers a lockdown mechanism (FR-15.1).
	LockdownAvailable bool `json:"lockdownAvailable"`
}

// clientsDetect lists the clients `clients setup` supports with whether
// each is installed for this user and set up by smcpctl (FR-20.10). It
// reads no Gateway configuration and changes nothing.
func clientsDetect(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("clients detect", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := harness.NewEnv(harness.Gateway{})
	if err != nil {
		return err
	}
	list := []detectedClient{}
	for _, c := range harness.Clients() {
		_, setupErr := os.Stat(harness.ManifestPath(e.Home, c.ID, "setup"))
		_, lockErr := os.Stat(harness.ManifestPath(e.Home, c.ID, "lockdown"))
		list = append(list, detectedClient{ID: c.ID, Name: c.Name, Installed: c.Installed(e), Connected: setupErr == nil,
			Lockdown: lockErr == nil, LockdownAvailable: c.LockdownMechanism != ""})
	}
	if *asJSON {
		printJSON(out, map[string]any{"clients": list})
		return nil
	}
	for _, c := range list {
		state := "not found"
		if c.Installed {
			state = "installed"
		}
		if c.Connected {
			state += ", set up"
		}
		fmt.Fprintf(out, "%-12s %-14s %s\n", c.ID, c.Name, state)
	}
	return nil
}

type changeJSON struct {
	Path    string `json:"path"`
	Scope   string `json:"scope"`
	Purpose string `json:"purpose"`
	Action  string `json:"action"` // create or update
	Content string `json:"content"`
}

type planJSON struct {
	Changes  []changeJSON `json:"changes"`
	Commands [][]string   `json:"commands"`
	Notes    []string     `json:"notes"`
}

type dryRunJSON struct {
	Client   string    `json:"client"`
	Name     string    `json:"name"`
	Setup    planJSON  `json:"setup"`
	Lockdown *planJSON `json:"lockdown"`
}

func planToJSON(p harness.Plan) planJSON {
	r := planJSON{Changes: []changeJSON{}, Commands: p.Commands, Notes: p.Notes}
	if r.Commands == nil {
		r.Commands = [][]string{}
	}
	if r.Notes == nil {
		r.Notes = []string{}
	}
	for _, c := range p.Changes {
		a := "create"
		if c.Before != nil {
			a = "update"
		}
		r.Changes = append(r.Changes, changeJSON{Path: c.Path, Scope: c.Scope, Purpose: c.Purpose, Action: a, Content: string(c.After)})
	}
	return r
}
