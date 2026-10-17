package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// checkPackagedBootstrap inspects the configuration bootstrap wrote
// (FR-14.10): one backend, the reference package by digest, no installer.
func checkPackagedBootstrap(t *testing.T, dir, raw string) {
	t.Helper()
	cfg, err := config.Load(filepath.Join(dir, "smcp.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("%d backends", len(cfg.Servers))
	}
	s := cfg.Servers[0]
	if s.Package != RefPackageID || len(s.PackageSHA256) != 64 || s.Command != "" || s.Slots["root"] == "" {
		t.Fatalf("server entry: %+v", s)
	}
	refSum, _, _ := packaging.FileSHA256(filepath.Join(binDir, "smcp-refserver"))
	if s.PackageSHA256 != refSum {
		t.Fatal("package_sha256 is not the reference server's digest")
	}
	if regexp.MustCompile(`(?m)^[^#\n]*(\bcommand\s*=|npx|uvx|pip )`).MatchString(raw) {
		t.Fatalf("installer or command in the example:\n%s", raw)
	}
	// The digest names a content-addressed artifact in the state directory.
	if _, err := os.Stat(filepath.Join(dir, "state", "packages", "artifacts", "sha256", s.PackageSHA256)); err != nil {
		t.Fatalf("artifact not in the content-addressed store: %v", err)
	}
	out := mustCtl(t, "package", "list", "--config", filepath.Join(dir, "smcp.toml"))
	if !strings.Contains(out, RefPackageID) || !strings.Contains(out, "enabled") {
		t.Fatalf("package list: %s", out)
	}
}

func TestBootstrapUsesPackagedServer(t *testing.T) {
	reqtest.Verifies(t, "FR-14.10")
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t))
	raw, _ := os.ReadFile(filepath.Join(dir, "smcp.toml"))
	checkPackagedBootstrap(t, dir, string(raw))
	// The Gateway serves the package as verified; health has no
	// unverified servers.
	cfgPath := filepath.Join(dir, "smcp.toml")
	d := startDaemon(t, cfgPath)
	out := mustCtl(t, "health", "--config", cfgPath)
	if strings.Contains(out, "unverified") || !strings.Contains(out, `"ref"`) {
		t.Fatalf("health: %s", out)
	}
	// With smcpd holding the registry, list goes through the control API.
	out = mustCtl(t, "package", "list", "--config", cfgPath)
	if !strings.Contains(out, `"status": "running"`) || !strings.Contains(out, RefPackageID) {
		t.Fatalf("package list via API: %s", out)
	}
	stopDaemon(t, d)
}

func TestPackageCommands(t *testing.T) {
	reqtest.Verifies(t, "FR-14.7")
	reqtest.Partial(t, "FR-14.1", "FR-14.6", "FR-14.8", "FR-14.12")
	work := t.TempDir()
	dir := filepath.Join(work, "inst")
	secrets := t.TempDir()
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", writeFile(t, secrets, "a", "admin password 12"),
		"--approver-password-file", writeFile(t, secrets, "b", "approver password 1"),
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t))
	cfgPath := filepath.Join(dir, "smcp.toml")
	ref := filepath.Join(binDir, "smcp-refserver")
	sum, _, _ := packaging.FileSHA256(ref)
	os.WriteFile(filepath.Join(work, "src.tar.gz"), []byte("source"), 0o644)
	recipe := map[string]any{
		"recipe_version": 1,
		"server":         map[string]any{"id": "echo-only", "alias": "echo", "publisher": "test"},
		"artifact":       map[string]any{"type": "binary", "reference": ref, "version": "2.0.0", "sha256": sum},
		"launch":         map[string]any{"runtime": "native", "argv": []string{"smcp-refserver"}},
		"risk_class":     "moderate",
		"instance_scope": []string{"shared"},
		"tools":          map[string]any{"default": map[string]any{"side_effect": "read", "source_trust": "trusted"}, "expect": []string{"echo"}},
		"capabilities":   map[string]any{"filesystem": []any{}, "egress": []any{}, "spawns_processes": false, "resources": map[string]any{}},
		"source":         map[string]any{"kind": "archive", "uri": "https://example.invalid/src.tar.gz", "path": "src.tar.gz"},
		"licenses":       []string{"Apache-2.0"},
	}
	rb, _ := json.Marshal(recipe)
	os.WriteFile(filepath.Join(work, "recipe.json"), rb, 0o644)
	pkg := filepath.Join(work, "pkg")
	out := mustCtl(t, "package", "build", "--recipe", filepath.Join(work, "recipe.json"), "--out", pkg)
	if !strings.Contains(out, "echo-only@2.0.0") || !strings.Contains(out, sum) {
		t.Fatal(out)
	}
	key := filepath.Join(work, "op")
	mustCtl(t, "package", "keygen", "--out", key, "--unencrypted")
	if st, _ := os.Stat(key + ".key"); st.Mode().Perm() != 0o600 {
		t.Fatalf("secret key mode %v", st.Mode())
	}
	// Keys and passphrases on the command line are refused (FR-14.6).
	for _, args := range [][]string{{"package", "sign", pkg, "--secret-key", "RWQ..."}, {"package", "sign", pkg, "--key", key + ".key", "--passphrase", "x"}} {
		if out, err := ctl(t, "", args...); err == nil || !strings.Contains(out, packaging.ReasonKeyOnCommandLine) {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	// Unsigned: verify names the missing signature.
	if out, err := ctl(t, "", "package", "verify", pkg, "--pubkey", key+".pub"); err == nil || !strings.Contains(out, packaging.ReasonSignatureMissing) {
		t.Fatalf("unsigned verify: %v %s", err, out)
	}
	mustCtl(t, "package", "sign", pkg, "--key", key+".key")
	if out := mustCtl(t, "package", "verify", pkg, "--pubkey", key+".pub"); !strings.Contains(out, "package OK") {
		t.Fatal(out)
	}
	// Not enrolled yet: verification against the anchors fails with exit 1.
	if out, err := ctl(t, "", "package", "verify", pkg, "--config", cfgPath); err == nil || !strings.Contains(out, packaging.ReasonSignerUnknown) {
		t.Fatalf("verify without anchor: %v %s", err, out)
	}
	// Modified manifest, modified artifact, wrong key: each fails, naming the check.
	other := filepath.Join(work, "other")
	mustCtl(t, "package", "keygen", "--out", other, "--unencrypted")
	if out, err := ctl(t, "", "package", "verify", pkg, "--pubkey", other+".pub"); err == nil || !strings.Contains(out, packaging.ReasonSignerUnknown) {
		t.Fatalf("wrong key: %v %s", err, out)
	}
	for _, f := range []string{packaging.ManifestFile, "artifact/smcp-refserver"} {
		cp := filepath.Join(work, "tamper-"+filepath.Base(f))
		packaging.CopyPackage(pkg, cp)
		p := filepath.Join(cp, filepath.FromSlash(f))
		b, _ := os.ReadFile(p)
		os.WriteFile(p, append(b, '\n'), 0o644)
		if out, err := ctl(t, "", "package", "verify", cp, "--pubkey", key+".pub"); err == nil || !strings.Contains(out, packaging.ReasonDigestMismatch) {
			t.Fatalf("tampered %s: %v %s", f, err, out)
		}
	}
	// Enroll with the default classes (low, moderate) and install.
	out = mustCtl(t, "trust", "add", key+".pub", "--name", "operator", "--config", cfgPath)
	if !strings.Contains(out, "low,moderate") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "trust", "list", "--config", cfgPath); !strings.Contains(out, "operator") || !strings.Contains(out, "bootstrap-") {
		t.Fatal(out)
	}
	out = mustCtl(t, "package", "install", pkg, "--config", cfgPath, "--enable")
	if !strings.Contains(out, "imported echo-only@2.0.0") || !strings.Contains(out, "enabled echo-only@2.0.0") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "package", "list", "--config", cfgPath); !strings.Contains(out, "echo-only") || !strings.Contains(out, "operator") {
		t.Fatal(out)
	}
	// Revoke offline: the revision becomes revoked.
	out = mustCtl(t, "package", "revoke", "echo-only@2.0.0", "--key", key+".key", "--reason", "test", "--config", cfgPath)
	if !strings.Contains(out, "is revoked") {
		t.Fatal(out)
	}
	out = mustCtl(t, "package", "list", "--config", cfgPath, "--json")
	if !strings.Contains(out, `"state": "revoked"`) {
		t.Fatal(out)
	}
	if out := mustCtl(t, "trust", "remove", "operator", "--config", cfgPath); !strings.Contains(out, "removed") {
		t.Fatal(out)
	}
}
