package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// bootstrapTokenLifetime bounds how long a one-use bootstrap token can be
// redeemed.
const bootstrapTokenLifetime = 24 * time.Hour

const exampleConfig = `# Secure MCP Gateway configuration.
# Validated against internal/config/config.schema.json at startup.

[listener]
address = %[1]q
public_url = %[2]q

[admin_listener]
address = %[3]q

[state]
dir = "state"

# Administrator of the control API (smcpctl stop/resume/policy reload use
# the operator token in state/keys/admin.token instead).
[admin]
username = "admin"
%[4]s

# Session Approvers approve harness sign-ins in the browser (FR-2.19). The
# administrator account cannot. Add more with smcpctl hash-password.
[[approver]]
username = "approver"
password_hash = %[5]q

[policy]
file = "policy.json"

# Framework instances (FR-2.1). The profile names a framework profile in policy.json.
[[principal]]
id = "claude-code-local"
framework = "claude-code"
display_name = "Claude Code on this machine"
profile = "dev"

# OAuth client registrations bound to a principal (FR-2.18). Claude Code
# identifies itself with this client ID and a loopback redirect on a random
# port.
[[client]]
client_id = "https://claude.ai/api/mcp/oauth/client-metadata"
principal = "claude-code-local"
redirect_uris = ["http://localhost:*/callback", "http://127.0.0.1:*/callback"]

# Backend MCP servers. The command must be an absolute path to a local
# artifact; package runners such as npx or uvx are refused (SR-3.6-1). The
# reference server below ships with the Gateway and offers read-only tools.
[[server]]
alias = "ref"
command = %[6]q
args = ["--root", %[7]q]
`

const examplePolicy = `{
  "revision": "r1",
  "framework_profiles": {
    "dev": { "templates": ["read-only", "approval-demo"], "default_template": "read-only" }
  },
  "templates": {
    "read-only": {
      "description": "Read the sandbox directory with the reference server",
      "rules": [
        { "id": "ro-ref", "server": "ref", "tools": ["echo", "time_now", "list_files", "read_file"] }
      ]
    },
    "approval-demo": {
      "description": "As read-only, but reading a file needs a person's approval",
      "rules": [
        { "id": "demo-free", "server": "ref", "tools": ["echo", "time_now", "list_files"] },
        { "id": "demo-approve", "server": "ref", "tools": ["read_file"], "approval": true }
      ]
    }
  }
}
`

// findRefserver locates the reference server: next to this executable, then
// on PATH. The result is absolute, because PATH lookup at launch time is
// refused.
func findRefserver() (string, error) {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "smcp-refserver")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	p, err := exec.LookPath("smcp-refserver")
	if err != nil {
		return "", errors.New("smcp-refserver not found next to smcpctl or on PATH; build it (go build ./cmd/smcp-refserver) or pass --refserver")
	}
	return filepath.Abs(p)
}

func bootstrap(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory for smcp.toml, policy.json and state/")
	adminFile := fs.String("admin-password-file", "", "read the administrator password from this file (- for standard input) instead of a prompt")
	approverFile := fs.String("approver-password-file", "", "read the Session Approver password from this file instead of a prompt")
	useToken := fs.Bool("bootstrap-token", false, "set no administrator password now; print a one-use token to set it later with `smcpctl admin redeem`")
	sandbox := fs.String("sandbox", "", "directory the reference server may read (default <dir>/sandbox)")
	refserver := fs.String("refserver", "", "path of smcp-refserver (default: next to smcpctl, then PATH)")
	port := fs.Int("port", 8443, "harness listener port on 127.0.0.1")
	adminPort := fs.Int("admin-port", 8444, "control API listener port on 127.0.0.1")
	if err := fs.Parse(args); err != nil {
		return err
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(abs, "smcp.toml")
	_, statErr := os.Stat(cfgPath)
	writeCfg := os.IsNotExist(statErr)

	var adminLine, token string
	var approverHash string
	if writeCfg {
		if *useToken {
			token = ids.Secret()
			sum := sha256.Sum256([]byte(token))
			adminLine = fmt.Sprintf("bootstrap_token_sha256 = %q\nbootstrap_token_expires = %q", hex.EncodeToString(sum[:]),
				time.Now().Add(bootstrapTokenLifetime).UTC().Format(time.RFC3339))
		} else {
			pw, err := readSecret(*adminFile, "Administrator password (12 or more characters)", true)
			if err != nil {
				return fmt.Errorf("administrator password: %w (or use --bootstrap-token)", err)
			}
			if len(pw) < 12 {
				return errors.New("administrator password must be at least 12 characters")
			}
			h, err := keys.HashPassword(pw)
			if err != nil {
				return err
			}
			adminLine = fmt.Sprintf("password_hash = %q", h)
		}
		apw, err := readSecret(*approverFile, "Session Approver password (approves harness sign-ins; 12 or more characters)", true)
		if err != nil {
			return fmt.Errorf("approver password: %w", err)
		}
		if len(apw) < 12 {
			return errors.New("approver password must be at least 12 characters")
		}
		if approverHash, err = keys.HashPassword(apw); err != nil {
			return err
		}
		if *refserver == "" {
			if *refserver, err = findRefserver(); err != nil {
				return err
			}
		}
		if *refserver, err = filepath.Abs(*refserver); err != nil {
			return err
		}
	}
	if *sandbox == "" {
		*sandbox = filepath.Join(abs, "sandbox")
	}
	if err := os.MkdirAll(*sandbox, 0o755); err != nil {
		return err
	}
	stateDir := filepath.Join(abs, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		return err
	}
	listen := fmt.Sprintf("127.0.0.1:%d", *port)
	if writeCfg {
		body := fmt.Sprintf(exampleConfig, listen, "https://"+listen, fmt.Sprintf("127.0.0.1:%d", *adminPort), adminLine, approverHash, *refserver, *sandbox)
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			return err
		}
		fmt.Fprintln(out, "wrote", cfgPath)
	} else {
		fmt.Fprintln(out, "kept existing", cfgPath)
	}
	polPath := filepath.Join(abs, "policy.json")
	if _, err := os.Stat(polPath); os.IsNotExist(err) {
		if err := os.WriteFile(polPath, []byte(examplePolicy), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(out, "wrote", polPath)
	} else {
		fmt.Fprintln(out, "kept existing", polPath)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if _, err := policy.Load(polPath); err != nil {
		return err
	}
	if token != "" {
		fmt.Fprintf(out, `
One-use bootstrap token (shown once, valid for 24 hours):

  %s

After starting smcpd, set the administrator password with:
  smcpctl admin redeem --config %s
`, token, cfgPath)
	}
	fmt.Fprintf(out, `
State and keys are under %s.

Next steps:
  1. Start the Gateway:        smcpd --config %s
  2. Trust the local CA:        export NODE_EXTRA_CA_CERTS=%s
  3. Register with Claude Code: claude mcp add --transport http smcp %s
     Claude Code opens a browser for OAuth; sign in as the Session Approver "approver".
  4. Check health:              smcpctl health --config %s
`, stateDir, cfgPath, filepath.Join(stateDir, keys.CACertFile), cfg.ResourceURI(), cfgPath)
	return nil
}
