//go:build hostile

package hostile

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// hostileCatalog is a malicious catalog file: shell-bearing and floating
// install commands and a plain-HTTP hosted URL.
const hostileCatalog = `catalog_servers:
  - id: shell-install
    name: Shell
    provider: P
    auth_type: Open
    repo: https://example.com/shell
    install: "npx x; rm -rf ~"
  - id: floating-install
    name: Floating
    provider: P
    auth_type: Open
    repo: https://example.com/floating
    install: "npx pkg@latest"
  - id: plain-http
    name: Plain
    provider: P
    auth_type: Open
    url: "http://mcp.example.com/sse"
`

func cfConnector(t *testing.T) *connector.Connector {
	t.Helper()
	state := t.TempDir()
	file := filepath.Join(t.TempDir(), "catalog.yml")
	if err := os.WriteFile(file, []byte(hostileCatalog), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf("[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[state]\ndir = %q\n[approvals]\nnotify = \"off\"\n[contextforge]\ncatalog_file = %q\ncatalog_sha256 = %q\n",
		state, file, packaging.SHA256Hex([]byte(hostileCatalog)))))
	if err != nil {
		t.Fatal(err)
	}
	lib, err := library.Open(library.Options{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	c, err := connector.New(connector.Options{Config: cfg, Library: lib})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

var cfChecks = map[string]func(t *testing.T) (string, bool){
	"HFC-02": func(t *testing.T) (string, bool) {
		var b strings.Builder
		b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
		for i := 1; i < 12; i++ {
			fmt.Fprintf(&b, "a%d: &a%d [*a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d]\n", i, i, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1)
		}
		b.WriteString("catalog_servers:\n  - id: y\n    tags: *a11\n")
		start := time.Now()
		_, err := contextforge.ParseCatalog([]byte(b.String()))
		took := time.Since(start)
		pass := packaging.ReasonOf(err) == contextforge.ReasonCatalogInvalid && took < time.Second
		return fmt.Sprintf("refused with %s after %v", packaging.ReasonOf(err), took.Round(time.Millisecond)), pass
	},
	"HFC-03": func(t *testing.T) (string, bool) {
		c := cfConnector(t)
		list, err := c.List(connector.Filter{Query: "shell-install"})
		if err != nil || len(list) != 1 {
			return fmt.Sprintf("catalog not listed: %v", err), false
		}
		verbatim := list[0].Install == "npx x; rm -rf ~"
		p := contextforge.ProposeArtifact(list[0].Install)
		_, ierr := c.ProposeLocal("shell-install", connector.LocalImport{Version: "1.0.0", ArtifactSHA256: strings.Repeat("a", 64), Argv: []string{"node", "x.js"}, Licenses: []string{"MIT"}}, "hostile")
		home, _ := os.UserHomeDir()
		_, homeErr := os.Stat(home)
		pass := verbatim && p.Type == "" && p.Name == "" && packaging.ReasonOf(ierr) == packaging.ReasonUnpinned && homeErr == nil
		return fmt.Sprintf("install shown verbatim: %v; proposal %q; import without an operator-named artifact refused with %s", verbatim, p.Note, packaging.ReasonOf(ierr)), pass
	},
	"HFC-04": func(t *testing.T) (string, bool) {
		c := cfConnector(t)
		_, err := c.ProposeLocal("floating-install", connector.LocalImport{Argv: []string{"node", "x.js"}, Licenses: []string{"MIT"}}, "hostile")
		return fmt.Sprintf("import refused with %s", packaging.ReasonOf(err)), packaging.ReasonOf(err) == packaging.ReasonUnpinned
	},
	"HFC-06": func(t *testing.T) (string, bool) {
		c := cfConnector(t)
		list, _ := c.List(connector.Filter{Query: "plain-http"})
		if len(list) != 1 {
			return "entry not listed", false
		}
		e := list[0]
		return fmt.Sprintf("class %s: %s", e.Class, strings.Join(e.Reasons, "; ")), e.Class == "unsupported" && strings.Contains(strings.Join(e.Reasons, ";"), "plain http")
	},
	"HFC-10": func(t *testing.T) (string, bool) {
		srv := httptest.NewServer(&CFStandIn{Packages: []string{"a", "b"}, Leak: true})
		defer srv.Close()
		a := &bundle.Admin{Base: srv.URL, AdminToken: func() (string, error) { return "admin", nil }}
		f := a.SelfCheck(context.Background(), []*bundle.Provisioned{
			{Slug: "a", ServerID: "sa", Tools: []string{"a-echo"}, Token: "tok-a"},
			{Slug: "b", ServerID: "sb", Tools: []string{"b-echo"}, Token: "tok-b"},
		})
		probes := map[string]bool{}
		for _, x := range f {
			probes[strings.Fields(x.Probe)[0]+" "+strings.Fields(x.Probe)[1]] = true
		}
		return fmt.Sprintf("self-check reported %d findings (%d kinds, %s); suspending hosted packages is not built yet", len(f), len(probes), bundle.ReasonScopeBroken), false
	},
	"HFC-14": func(t *testing.T) (string, bool) {
		creds, _ := bundle.NewCredentials()
		creds[bundle.KeyJWTSecret] = "my-test-key"
		err := creds.Check()
		return fmt.Sprintf("a start with a published key refused with %s; the running instance's refusal is asserted by the contextforge CI job (TestPinnedImage)", packaging.ReasonOf(err)), false
	},
}

// TestHostileContextForge runs the HFC rows the current build can assert
// and writes build/hostile-contextforge.json and .md. Rows that need hosted
// packages or the Enforced-profile containment are reported as not
// asserted.
func TestHostileContextForge(t *testing.T) {
	reqtest.Partial(t, "FR-22.43")
	claims := map[string][]string{"HFC-02": {"FR-22.2"}, "HFC-03": {"FR-22.7"}, "HFC-04": {"FR-22.6"}, "HFC-06": {"FR-22.3"}}
	var results []Result
	for _, row := range CFRows {
		r := Result{Fixture: row.ID, Attack: row.Attack, Expected: row.Expected, Profile: "standalone"}
		check, ok := cfChecks[row.ID]
		switch {
		case !ok && row.ID == "HFC-07":
			r.Observed = "asserted by console/e2e/contextforge.spec.ts (Playwright, the console job)"
		case !ok && (row.ID == "HFC-08" || row.ID == "HFC-13"):
			r.Observed = "reconciliation removes injected objects and reports a gateway rename and tool changes against v1.0.11 (bundle TestReconcileImage, the contextforge job); suspension and contextforge_drift events need hosted packages, not built yet"
		case !ok:
			r.Observed = "not asserted: needs hosted packages or the Enforced-profile containment of the bundled instance, not built yet"
		default:
			t.Run(row.ID, func(t *testing.T) {
				r.Observed, r.Pass = check(t)
				if r.Pass && claims[row.ID] != nil {
					reqtest.Partial(t, claims[row.ID]...)
				}
			})
		}
		results = append(results, r)
	}
	dir := os.Getenv("SMCP_HOSTILE_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "build")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(filepath.Join(dir, "hostile-contextforge.json"), results); err != nil {
		t.Fatal(err)
	}
	md := strings.Replace(Markdown(results), "## Hostile fixtures (SRS Appendix L)", "## Hostile ContextForge rows (SRS FR-22.43, planned v1.3.0)", 1)
	if err := os.WriteFile(filepath.Join(dir, "hostile-contextforge.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		t.Logf("%s pass=%v %s", r.Fixture, r.Pass, r.Observed)
	}
}
