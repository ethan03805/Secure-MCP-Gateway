//go:build linux

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestEnforcedClientViewOnHost runs as the CI runner's own account (not
// root, not in group smcp) on a host where scripts/ci-systemd.sh installed
// the Enforced profile and started smcpd.service. That account cannot read
// /etc/smcp/smcp.toml or the state directory, as a desktop user cannot;
// the Gateway's client view in /var/lib/smcp/public gives it the CA
// certificate (the same bundle as the state directory's) and the
// addresses. With them the account verifies the admin and harness
// listeners' certificates against that CA only, as the console window does
// (SR-2.8-5), and `smcpctl connect --config /etc/smcp/smcp.toml` plans a
// client setup that names the published CA (FR-20.10).
func TestEnforcedClientViewOnHost(t *testing.T) {
	if os.Getenv("SMCP_ENFORCED_HOST_TEST") != "1" {
		t.Skip("needs an Enforced installation with smcpd.service running; set SMCP_ENFORCED_HOST_TEST=1 (scripts/ci-systemd.sh)")
	}
	reqtest.Partial(t, "SR-2.8-5", "FR-20.10")
	if os.Geteuid() == 0 {
		t.Fatal("run as the unprivileged runner account, not root")
	}
	if u, err := user.Current(); err == nil {
		if gids, err := u.GroupIds(); err == nil {
			if g, err := user.LookupGroup("smcp"); err == nil {
				for _, id := range gids {
					if id == g.Gid {
						t.Fatalf("%s is a member of group smcp, so this test would not show what a desktop user sees", u.Username)
					}
				}
			}
		}
	}
	const cfgPath = "/etc/smcp/smcp.toml"
	if _, err := os.ReadFile(cfgPath); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("%s is readable by this account or missing (%v); the test needs the Enforced modes", cfgPath, err)
	}
	stateCA, err := sudoOut(t, "", "cat", filepath.Join("/var/lib/smcp/state", keys.CACertFile))
	if err != nil {
		t.Fatalf("sudo cat state CA: %v %s", err, stateCA)
	}
	pub := config.EnforcedPublicDir
	if st, err := os.Stat(pub); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("%s: %v %v", pub, err, st)
	}
	ca, err := os.ReadFile(filepath.Join(pub, config.PublicCAFile))
	if err != nil {
		t.Fatalf("this account cannot read the published CA: %v", err)
	}
	if !bytes.Equal(ca, []byte(stateCA)) {
		t.Fatal("the published CA differs from the state directory's trust bundle")
	}
	view, err := config.LoadClientView(pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(pub, config.ClientViewFile))
	for _, s := range []string{"argon2", "password", "token", "secret"} {
		if strings.Contains(strings.ToLower(string(raw)), s) {
			t.Fatalf("the client view mentions %q", s)
		}
	}

	// The CA alone verifies both listeners, with their configured names.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("no certificate in the published CA")
	}
	for _, u := range []string{view.AdminURL, view.MCPURL} {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", pu.Host, &tls.Config{RootCAs: pool, ServerName: pu.Hostname(), MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatalf("%s does not verify against the published CA: %v", u, err)
		}
		conn.Close()
		t.Logf("%s verified against %s", u, filepath.Join(pub, config.PublicCAFile))
	}

	// smcpctl connect as this account, as the desktop client window runs it.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())
	code, out, errs := rctl(t, "connect", "claude-code", "--config", cfgPath, "--dry-run", "--json", "--no-lockdown")
	if code != 0 {
		t.Fatalf("smcpctl connect --config %s as this account: %d %s %s", cfgPath, code, out, errs)
	}
	if !strings.Contains(out, view.MCPURL) || !strings.Contains(out, filepath.Join(pub, config.PublicCAFile)) {
		t.Fatalf("the plan does not name %s and the published CA:\n%s", view.MCPURL, out)
	}
	// And the installed smcpctl binary, with its note on standard error.
	bin := "/usr/local/bin/smcpctl"
	if _, err := os.Stat(bin); err == nil {
		cmd := exec.Command(bin, "connect", "claude-code", "--config", cfgPath, "--dry-run", "--no-lockdown")
		cmd.Env = append(os.Environ(), "HOME="+home)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil || !strings.Contains(stderr.String(), "client view") || !strings.Contains(string(b), "dry run") {
			t.Fatalf("%s connect: %v\n%s\n%s", bin, err, b, stderr.String())
		}
	}
}
