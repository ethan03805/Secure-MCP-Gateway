package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The recorded ContextForge v1.0.11 catalog (see internal/contextforge).
var (
	cfFixture       = filepath.Join(repoRoot, "internal", "contextforge", "testdata", "mcp-catalog-v1.0.11.yml")
	cfFixtureSHA256 = "f6be59e31f1017487c8c882fa86b2594214e50b7bcf784773a5a4e0651e91daa"
)

func runCatalog(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"catalog"}, args...), &out, &errb)
	return out.String(), errb.String(), code
}

func TestCatalogNeedsExperimentalFlag(t *testing.T) {
	_, stderr, code := runCatalog(t, "list", "--catalog", cfFixture)
	if code == 0 || !strings.Contains(stderr, "--experimental-contextforge") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
}

func TestCatalogImportOnlyDryRun(t *testing.T) {
	_, stderr, code := runCatalog(t, "import", "--experimental-contextforge", "--catalog", cfFixture, "deepwiki")
	if code == 0 || !strings.Contains(stderr, "only --dry-run") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
}

func TestCatalogSHA256Pin(t *testing.T) {
	_, stderr, code := runCatalog(t, "list", "--experimental-contextforge", "--catalog", cfFixture, "--sha256", strings.Repeat("0", 64))
	if code == 0 || !strings.Contains(stderr, cfFixtureSHA256) {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	out, stderr, code := runCatalog(t, "list", "--experimental-contextforge", "--catalog", cfFixture, "--sha256", cfFixtureSHA256, "--class", "local")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if !strings.Contains(out, "(confirmed), 4 of 135 entries") || !strings.Contains(out, "npx -y @azure-devops/mcp") {
		t.Fatalf("list output:\n%s", out)
	}
}

func TestCatalogListJSON(t *testing.T) {
	out, stderr, code := runCatalog(t, "list", "--experimental-contextforge", "--catalog", cfFixture, "--json")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	var doc struct {
		SHA256  string `json:"catalog_sha256"`
		Entries []struct {
			ID, Class string
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SHA256 != cfFixtureSHA256 || len(doc.Entries) != 135 {
		t.Fatalf("sha %s entries %d", doc.SHA256, len(doc.Entries))
	}
}

func TestCatalogImportDryRunHosted(t *testing.T) {
	// Flags after the entry ID are accepted.
	out, stderr, code := runCatalog(t, "import", "--experimental-contextforge", "--catalog", cfFixture, "deepwiki", "--dry-run", "--release", "v1.0.11")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	var d struct {
		Class  string `json:"class"`
		Hosted struct {
			ManifestVersion int `json:"manifest_version"`
			Upstream        struct {
				Kind, URL string
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
	if d.Class != "hosted" || d.Hosted.ManifestVersion != 2 || d.Hosted.Upstream.Kind != "contextforge-hosted" || d.Hosted.Upstream.URL != "https://mcp.deepwiki.com/mcp" {
		t.Fatalf("draft %+v", d)
	}
	if d.Provenance.CatalogSHA256 != cfFixtureSHA256 || d.Provenance.Release != "v1.0.11" {
		t.Fatalf("provenance %+v", d.Provenance)
	}
}

func TestCatalogImportDryRunLocalWritesNothing(t *testing.T) {
	abs, err := filepath.Abs(cfFixture)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	out, stderr, code := runCatalog(t, "import", "--dry-run", "--experimental-contextforge", "--catalog", abs, "--version", "2.2.0", "--artifact-sha256", strings.Repeat("ab", 32), "azure-devops-mcp")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if !strings.Contains(out, `"recipe"`) || !strings.Contains(out, `"reference": "@azure-devops/mcp"`) || !strings.Contains(out, `"version": "2.2.0"`) {
		t.Fatalf("draft:\n%s", out)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("dry run wrote %v", ents)
	}
	_, stderr, code = runCatalog(t, "import", "--dry-run", "--experimental-contextforge", "--catalog", abs, "--artifact-sha256", "XYZ", "azure-devops-mcp")
	if code == 0 || !strings.Contains(stderr, "64 lowercase hex") {
		t.Fatalf("bad digest accepted: %q", stderr)
	}
}

func TestCatalogRefusesHostileFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yml")
	if err := os.WriteFile(f, []byte("x: &a [1]\ncatalog_servers:\n  - id: y\n    tags: *a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCatalog(t, "list", "--experimental-contextforge", "--catalog", f)
	if code == 0 || !strings.Contains(stderr, "not allowed") {
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
