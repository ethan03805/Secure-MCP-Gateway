package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestLeakFingerprintsWiring builds the Secret Broker, the Observation
// Collector's service and the Gateway the way run() does (attachSecrets,
// then app.Start), delivers a secret through the broker (S4, as at a
// launch) and checks that the delivered value is detected raw,
// Base64-encoded, hex-encoded, URL-encoded and as a 12-character fragment
// by both registrations FR-6.10 names: the Response Inspection Pipeline's
// fingerprint set (E-11) and the Observation Collector's scanner (E-29).
// Text without the secret matches neither, and nothing matches before the
// delivery. The derivation itself (keyed HMAC-SHA-256 over every
// 12-character substring of each form, no plaintext kept) is covered by
// internal/secrets.TestFingerprintsDetectEncodedForms and
// TestFingerprintSetHoldsNoPlaintext; a leaked result withheld with
// SECRET_LEAK by internal/secrets.TestBrokerLeakDetectionNorthbound and
// HF-08.
func TestLeakFingerprintsWiring(t *testing.T) {
	reqtest.Verifies(t, "FR-6.10")
	const secret = "smcpd-wired-secret-0123456789-abcdef"
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	pol := `{"revision": "r1", "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}}, "templates": {"t": {"rules": []}}}`
	use := `{"revision": "u1", "policies": [{"id": "env", "secret": "api-token", "server": "t", "slot": "API_TOKEN", "mode": "S4", "tools": ["*"],
  "purpose": "test", "s4_waiver": {"approved_by": "admin:test", "reason": "the server reads only its environment"}}]}`
	for name, body := range map[string]string{"policy.json": pol, "use.json": use, "pp": "fr-6.10 test passphrase\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	toml := fmt.Sprintf(`
[listener]
address = "127.0.0.1:1"
public_url = "https://127.0.0.1:1"
[admin_listener]
address = "127.0.0.1:2"
[state]
dir = %q
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[policy]
file = %q
[approvals]
notify = "off"
[observation]
store = "jsonl"
[secrets]
key_source = "passphrase"
passphrase_file = "pp"
use_policy_file = "use.json"
runtime_dir = "run"
[[server]]
alias = "t"
command = "/inproc/t"
[server.secret_env]
API_TOKEN = "api-token"
`, state, filepath.Join(dir, "policy.json"))
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	set, _ := secrets.SettingsFrom(cfg)
	ks := secrets.Passphrase{Path: filepath.Join(set.VaultDir, secrets.MasterKeyFile),
		Passphrase: func() (string, error) { return "fr-6.10 test passphrase", nil }, WorkFactor: 10}
	if _, err := secrets.Init(set.VaultDir, ks); err != nil {
		t.Fatal(err)
	}

	log := diag.Discard()
	obs, err := analytics.New(analytics.Options{Config: cfg, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	defer obs.Close()
	// The server's launch is the delivery: app.Start launches "t" through
	// the broker-wrapped launcher, which resolves API_TOKEN (S4).
	rec := &envRecorder{InProcessLauncher: pipeline.InProcessLauncher{Servers: map[string]func() *mcp.Server{
		"/inproc/t": func() *mcp.Server { return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil) }}}}
	opts := app.Options{Log: log, Host: &profile.Host{OS: "darwin", Arch: "arm64"}, Launcher: rec}
	sec, err := attachSecrets(cfg, &opts, obs, health.New(health.Options{Log: log}), log)
	if err != nil || sec == nil {
		t.Fatalf("attachSecrets: %v %v", sec, err)
	}
	defer sec.Close()
	sec.Vault.SetEvidence(&audit.Memory{}) // app.Start replaces it with the journal
	if _, err := sec.Vault.Create("admin:test", secrets.CreateParams{Name: "api-token", Type: "api_key", Value: []byte(secret)}); err != nil {
		t.Fatal(err)
	}

	forms := map[string]string{
		"raw":      "result: " + secret,
		"base64":   base64.StdEncoding.EncodeToString([]byte(secret)),
		"hex":      hex.EncodeToString([]byte(secret)),
		"url":      url.QueryEscape("q=" + secret + "&x=1"),
		"fragment": "...." + secret[7:19] + "....",
	}
	for name, text := range forms {
		if n := obs.SecretMatches([]byte(text)); n != 0 {
			t.Fatalf("%s: the collector matched before delivery (%d)", name, n)
		}
	}
	a, err := app.Start(context.Background(), cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if got := rec.get("API_TOKEN"); got != secret {
		t.Fatalf("the secret was not delivered at launch (API_TOKEN set: %v)", got != "")
	}
	inspector := a.Inspector.Fingerprints()
	for name, text := range forms {
		if ref, ok := inspector.Match(text); !ok {
			t.Errorf("%s: the Response Inspection Pipeline does not detect the delivered secret", name)
		} else if ref == "" {
			t.Errorf("%s: match without a secret reference", name)
		}
		if n := obs.SecretMatches([]byte(text)); n < 1 {
			t.Errorf("%s: the Observation Collector does not detect the delivered secret", name)
		}
	}
	clean := "an ordinary result with nothing secret in it"
	if _, ok := inspector.Match(clean); ok {
		t.Error("the inspector matched clean text")
	}
	if n := obs.SecretMatches([]byte(clean)); n != 0 {
		t.Errorf("the collector matched clean text (%d)", n)
	}
}

// envRecorder is an in-process launcher that records the environment of
// the last launch.
type envRecorder struct {
	pipeline.InProcessLauncher
	mu  sync.Mutex
	env map[string]string
}

func (e *envRecorder) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	e.mu.Lock()
	e.env = maps.Clone(spec.Env)
	e.mu.Unlock()
	return e.InProcessLauncher.Launch(ctx, spec)
}

func (e *envRecorder) get(k string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.env[k]
}
