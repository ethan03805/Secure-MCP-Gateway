package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestReferenceRun bootstraps a real Gateway and runs every scenario with the
// scripted reference client (pass) and with a client that never calls a tool
// (fail), so a client that does not reach the Gateway cannot pass.
func TestReferenceRun(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")
	if testing.Short() {
		t.Skip("builds and starts smcpd")
	}
	silent := &client{ID: "silent", Name: "silent client", Framework: "other",
		run: func(ctx context.Context, e *runEnv, s scenario) (string, error) { return "I did nothing.", nil }}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := run(ctx, options{
		clients: "reference,silent", out: filepath.Join(dir, "agents.json"), report: filepath.Join(dir, "report.json"),
		work: filepath.Join(dir, "work"), timeout: time.Minute, maxTurns: 2, extra: []*client{silent},
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("results: %+v", res)
	}
	if res[0].Result != resultPass || res[0].Mode != modeScripted {
		t.Fatalf("reference client: %+v", res[0])
	}
	if !strings.Contains(res[0].Detail, "held and approved 1 with smcpctl") || !strings.Contains(res[0].Detail, "journal verify ok") {
		t.Fatalf("reference detail: %s", res[0].Detail)
	}
	if res[1].Result != resultFail || !strings.Contains(res[1].Detail, "no call to ref_echo") || !strings.Contains(res[1].Detail, "ungranted (not proven") {
		t.Fatalf("silent client must fail: %+v", res[1])
	}

	// agents.json follows the status contract: exactly these keys.
	b, err := os.ReadFile(filepath.Join(dir, "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(b, &arr); err != nil {
		t.Fatal(err)
	}
	for _, m := range arr {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"client", "detail", "mode", "result", "version"}) {
			t.Fatalf("agents.json keys %v", keys)
		}
	}
	var rep []clientReport
	b, _ = os.ReadFile(filepath.Join(dir, "report.json"))
	if err := json.Unmarshal(b, &rep); err != nil || len(rep) != 2 || len(rep[0].Scenarios) != 6 || rep[0].SessionID == "" {
		t.Fatalf("report: %v %+v", err, rep)
	}
}

func TestMatrixClientsCovered(t *testing.T) {
	reqtest.Partial(t, "FR-15.8", "FR-15.10")
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "docs/clients/matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Clients []struct {
			Client string `json:"client"`
			RunsOn string `json:"runsOn"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range allClients() {
		names[c.Name] = true
	}
	for _, c := range m.Clients {
		if c.RunsOn == "local" && !names[c.Client] {
			t.Errorf("local matrix client %q has no driver", c.Client)
		}
	}
	pins, err := loadPinned(filepath.Join(root, "docs/clients/matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range pins {
		if v == "" {
			t.Errorf("%s: empty pinned version", name)
		}
	}
	if p, err := loadPinned(filepath.Join(t.TempDir(), "missing.json")); err != nil || len(p) != 0 {
		t.Fatalf("missing matrix: %v %v", p, err)
	}
}

func TestSelectClients(t *testing.T) {
	all, err := selectClients("", nil)
	if err != nil || len(all) != len(allClients()) {
		t.Fatalf("default: %d %v", len(all), err)
	}
	if slices.ContainsFunc(all, func(c *client) bool { return c.ID == "reference" }) {
		t.Fatal("the reference client must not run by default")
	}
	got, err := selectClients("codex, reference", nil)
	if err != nil || len(got) != 2 || got[0].ID != "codex" || got[1].ID != "reference" {
		t.Fatalf("selection: %v", err)
	}
	if _, err := selectClients("nope", nil); err == nil {
		t.Fatal("unknown client accepted")
	}
}

// TestCommandsKeepSecretsOutOfArgv: the session token and the model key
// reach agent processes only through the environment (or, for Goose, an
// owner-only file), never through argv, which other local users can read.
func TestCommandsKeepSecretsOutOfArgv(t *testing.T) {
	const key, token = "aigw-test-key-0123456789", "session-token-0123456789"
	t.Setenv(aiKeyEnv, key)
	dir := t.TempDir()
	g := &gateway{endpoint: "https://127.0.0.1:1/mcp", ca: filepath.Join(dir, "ca.crt")}
	for _, local := range []bool{false, true} {
		for _, c := range allClients() {
			if c.command == nil {
				continue
			}
			e := &runEnv{g: g, dir: filepath.Join(dir, c.ID), token: token, local: local && c.LocalLogin, caBundle: g.ca, maxTurns: 2, bin: "/bin/" + c.ID}
			if err := os.MkdirAll(e.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := c.setup(c, e); err != nil {
				t.Fatalf("%s setup: %v", c.ID, err)
			}
			cmd := c.command(c, e, "prompt")
			argv := strings.Join(cmd.Args, " ")
			if strings.Contains(argv, key) || strings.Contains(argv, token) {
				t.Errorf("%s (local=%v): secret in argv: %s", c.ID, local, argv)
			}
			if !slices.Contains(cmd.Env, tokenEnv+"="+token) {
				t.Errorf("%s: %s not in the environment", c.ID, tokenEnv)
			}
			// Configuration files carry references, not secrets (Goose excepted).
			entries, _ := os.ReadDir(e.dir)
			for _, ent := range entries {
				if ent.IsDir() {
					continue
				}
				b, _ := os.ReadFile(filepath.Join(e.dir, ent.Name()))
				if strings.Contains(string(b), key) || strings.Contains(string(b), token) {
					t.Errorf("%s: secret written to %s", c.ID, ent.Name())
				}
			}
		}
	}
}

func TestRedactAndDiagnose(t *testing.T) {
	out := redact([]byte("Bearer abcdefgh12345 and key zzzzzzzzzz"), "abcdefgh12345", "zzzzzzzzzz", "short")
	if strings.Contains(string(out), "abcdefgh12345") || strings.Contains(string(out), "zzzzzzzzzz") {
		t.Fatalf("not redacted: %s", out)
	}
	dir := t.TempDir()
	if diagnose(dir) != "" {
		t.Fatal("empty directory diagnosed")
	}
	if err := os.WriteFile(filepath.Join(dir, "allowed.log"), []byte("error=unsupported name constraint type"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diagnose(dir), "CP-53") {
		t.Fatalf("diagnosis: %q", diagnose(dir))
	}
}

func TestDNSOnlyCA(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := reissueDNSOnlyCA(dir); err != nil {
		t.Fatal(err)
	}
	load := func(name string) *x509.Certificate {
		b, err := os.ReadFile(filepath.Join(dir, "tls", name))
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ca, leaf := load("ca.crt"), load("server.crt")
	if len(ca.PermittedIPRanges) != 0 || !slices.Equal(ca.PermittedDNSDomains, []string{"localhost"}) {
		t.Fatalf("constraints: dns %v ip %v", ca.PermittedDNSDomains, ca.PermittedIPRanges)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	if st, _ := os.Stat(filepath.Join(dir, "tls", "ca.key")); st.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode %v", st.Mode())
	}
}

func TestConfigAppendix(t *testing.T) {
	s := configAppendix([]*client{claudeCode(), codex()})
	for _, want := range []string{`notify = "off"`, `id = "agents-claude-code"`, `framework = "codex"`, `client_id = "smcp-agents-codex"`, `profile = "conformance"`} {
		if !strings.Contains(s, want) {
			t.Errorf("appendix lacks %s:\n%s", want, s)
		}
	}
	pol := conformancePolicy()
	b, _ := json.Marshal(pol)
	if strings.Contains(string(b), toolUngranted) {
		t.Fatal("policy grants the ungranted tool")
	}
}
