package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The catalog of the pinned ContextForge v1.0.11 release (see
// internal/contextforge/release).
var (
	cfFixture       = filepath.Join(repoRoot, "internal", "contextforge", "release", "mcp-catalog-v1.0.11.yml")
	cfFixtureSHA256 = "f6be59e31f1017487c8c882fa86b2594214e50b7bcf784773a5a4e0651e91daa"
)

func runCatalog(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"catalog"}, args...), &out, &errb)
	return out.String(), errb.String(), code
}

func TestCatalogPinnedByDefault(t *testing.T) {
	out, stderr, code := runCatalog(t, "list", "--class", "local")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if !strings.Contains(out, "ContextForge v1.0.11 catalog (pinned, sha256 "+cfFixtureSHA256+"), 4 of 135 entries") || !strings.Contains(out, "npx -y @azure-devops/mcp") {
		t.Fatalf("list output:\n%s", out)
	}
	// The flag of the v1.2 experiment is still accepted.
	if _, stderr, code := runCatalog(t, "list", "--experimental-contextforge"); code != 0 {
		t.Fatalf("old flag: code %d stderr %q", code, stderr)
	}
}

// Without --dry-run, import goes through the running Gateway.
func TestCatalogImportNeedsGateway(t *testing.T) {
	t.Chdir(t.TempDir())
	_, stderr, code := runCatalog(t, "import", "deepwiki")
	if code == 0 || !strings.Contains(stderr, "smcp.toml") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if _, stderr, code := runCatalog(t, "list", "--config", "x.toml", "--catalog", cfFixture); code == 0 || !strings.Contains(stderr, "offline") {
		t.Fatalf("--catalog with --config: %d %q", code, stderr)
	}
}

func TestCatalogOperatorFileNeedsConfirmedDigest(t *testing.T) {
	for _, extra := range [][]string{nil, {"--sha256", strings.Repeat("0", 64)}} {
		_, stderr, code := runCatalog(t, append([]string{"list", "--catalog", cfFixture}, extra...)...)
		if code == 0 || !strings.Contains(stderr, "CATALOG_DIGEST_MISMATCH") {
			t.Fatalf("%v: code %d stderr %q", extra, code, stderr)
		}
	}
	if _, stderr, code := runCatalog(t, "list", "--sha256", cfFixtureSHA256); code == 0 || !strings.Contains(stderr, "--catalog") {
		t.Fatalf("--sha256 alone: code %d stderr %q", code, stderr)
	}
	out, stderr, code := runCatalog(t, "list", "--catalog", cfFixture, "--sha256", cfFixtureSHA256, "--class", "local")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if !strings.Contains(out, "operator catalog (sha256 "+cfFixtureSHA256+", confirmed), 4 of 135 entries") {
		t.Fatalf("list output:\n%s", out)
	}
}

func TestCatalogListJSON(t *testing.T) {
	out, stderr, code := runCatalog(t, "list", "--json")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	var doc struct {
		SHA256  string `json:"catalog_sha256"`
		Origin  string `json:"origin"`
		Release string `json:"release"`
		Entries []struct {
			ID, Class string
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SHA256 != cfFixtureSHA256 || len(doc.Entries) != 135 || doc.Origin != "pinned" || doc.Release != "v1.0.11" {
		t.Fatalf("sha %s entries %d origin %s release %s", doc.SHA256, len(doc.Entries), doc.Origin, doc.Release)
	}
}

func TestCatalogShow(t *testing.T) {
	out, stderr, code := runCatalog(t, "show", "playwright-mcp")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	for _, want := range []string{"class                local", "install (text only)  npx @playwright/mcp@latest", "proposed artifact", "is not exact"} {
		if !strings.Contains(out, want) {
			t.Errorf("show output lacks %q:\n%s", want, out)
		}
	}
	out, _, code = runCatalog(t, "show", "deepwiki", "--json")
	var doc struct {
		Class string         `json:"class"`
		Entry map[string]any `json:"entry"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc.Class != "hosted" || doc.Entry["url"] != "https://mcp.deepwiki.com/mcp" {
		t.Fatalf("show --json: %d %s", code, out)
	}
	if _, stderr, code := runCatalog(t, "show", "no-such"); code == 0 || !strings.Contains(stderr, "no such catalog entry") {
		t.Fatalf("unknown entry: %d %q", code, stderr)
	}
}

func TestCatalogImportDryRunHosted(t *testing.T) {
	// Flags after the entry ID are accepted.
	out, stderr, code := runCatalog(t, "import", "deepwiki", "--dry-run")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	var d struct {
		Class  string `json:"class"`
		Hosted struct {
			ManifestVersion int `json:"manifest_version"`
			Upstream        struct {
				Kind        string `json:"kind"`
				URL         string `json:"url"`
				GatewayName string `json:"gateway_name"`
				GatewaySlug string `json:"gateway_slug"`
			} `json:"upstream"`
		} `json:"hosted_manifest"`
		Provenance struct {
			CatalogSHA256 string `json:"catalog_sha256"`
			Release       string `json:"contextforge_release"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	u := d.Hosted.Upstream
	if d.Class != "hosted" || d.Hosted.ManifestVersion != 2 || u.Kind != "contextforge-hosted" || u.URL != "https://mcp.deepwiki.com/mcp" || u.GatewayName != "smcp-deepwiki" || u.GatewaySlug != u.GatewayName {
		t.Fatalf("draft %+v", d)
	}
	// The pinned catalog supplies the release.
	if d.Provenance.CatalogSHA256 != cfFixtureSHA256 || d.Provenance.Release != "v1.0.11" {
		t.Fatalf("provenance %+v", d.Provenance)
	}
}

func TestCatalogImportDryRunLocalWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	out, stderr, code := runCatalog(t, "import", "--dry-run", "--version", "2.2.0", "--artifact-sha256", strings.Repeat("ab", 32), "azure-devops-mcp")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if !strings.Contains(out, `"recipe"`) || !strings.Contains(out, `"reference": "@azure-devops/mcp"`) || !strings.Contains(out, `"version": "2.2.0"`) {
		t.Fatalf("draft:\n%s", out)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("dry run wrote %v", ents)
	}
	_, stderr, code = runCatalog(t, "import", "--dry-run", "--artifact-sha256", "XYZ", "azure-devops-mcp")
	if code == 0 || !strings.Contains(stderr, "64 lowercase hex") {
		t.Fatalf("bad digest accepted: %q", stderr)
	}
}

func TestCatalogRefusesHostileFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yml")
	raw := []byte("x: &a [1]\ncatalog_servers:\n  - id: y\n    tags: *a\n")
	if err := os.WriteFile(f, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := packaging.SHA256Hex(raw)
	_, stderr, code := runCatalog(t, "list", "--catalog", f, "--sha256", sum)
	if code == 0 || !strings.Contains(stderr, "CATALOG_INVALID") || !strings.Contains(stderr, "not allowed") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
}

func TestInertText(t *testing.T) {
	if got := inert("ok\x1b[31mred\u202eevil\tx", 100); strings.ContainsAny(got, "\x1b\u202e\t") {
		t.Fatalf("control characters kept: %q", got)
	}
	if got := inert(strings.Repeat("a", 10), 4); got != "aaaa..." {
		t.Fatalf("cut %q", got)
	}
}

// TestCatalogImportProbeSecret: --probe-secret names the vault secret of a
// hosted entry's probe, with its header, and the request carries the
// name only (FR-22.9); without it the request has no probe_secret.
func TestCatalogImportProbeSecret(t *testing.T) {
	reqtest.Partial(t, "FR-22.9")
	body := map[string]any{}
	addProbeSecret(body, "", "X-Api-Key", "")
	if _, ok := body["probe_secret"]; ok {
		t.Fatal("probe_secret without --probe-secret")
	}
	addProbeSecret(body, "docs-key", "X-Api-Key", "{secret}")
	raw, _ := json.Marshal(body)
	if string(raw) != `{"probe_secret":{"header":"X-Api-Key","secret":"docs-key","template":"{secret}"}}` {
		t.Fatalf("body %s", raw)
	}
	var in connector.LocalImport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.ProbeSecret == nil || in.ProbeSecret.Secret != "docs-key" {
		t.Fatalf("the Gateway reads %+v: %v", in, err)
	}
}
