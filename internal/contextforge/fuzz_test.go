package contextforge

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Fuzz targets of the security review of v1.3.0
// (docs/security-review-v1.3.md). A fuzzing run is
// go test -run '^$' -fuzz FuzzParseCatalog ./internal/contextforge.

// FuzzParseCatalog: an operator-supplied catalog is untrusted text. The
// parser never panics, keeps the FR-22.2 bounds on what it accepts, and
// every accepted entry can be classified and drafted without an install
// string turning into a command line with shell syntax.
func FuzzParseCatalog(f *testing.F) {
	// FR-22.2 in part: the bounds hold for every input; the time and
	// memory bounds are TestBoundedParsing's.
	reqtest.Partial(f, "FR-22.2")
	for _, s := range []string{
		"catalog_servers:\n  - id: a\n    name: A\n    url: https://mcp.example.com/sse\n    auth_type: OAuth2.1\n",
		"catalog_servers:\n  - id: fs\n    install: npx -y @modelcontextprotocol/server-filesystem@1.0.0\n",
		"catalog_servers:\n  - id: x\n    install: \"uvx pkg; rm -rf /\"\n",
		"catalog_servers:\n  - &a {id: a}\n  - *a\n",
		"catalog_servers:\n  - id: a\n    <<: {x: 1}\n",
		"catalog_servers: [{id: a}, {id: a}]\n",
		"a: !!binary aGk=\n",
		"---\ncatalog_servers: []\n---\n",
		strings.Repeat("[", 64) + strings.Repeat("]", 64),
	} {
		f.Add([]byte(s))
	}
	shell := regexp.MustCompile("[;&|<>$`]")
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := ParseCatalog(raw)
		if err != nil {
			return
		}
		if len(raw) > MaxCatalogBytes || len(c.Entries) > MaxEntries {
			t.Fatalf("accepted %d bytes with %d entries", len(raw), len(c.Entries))
		}
		seen := map[string]bool{}
		for _, e := range c.Entries {
			if e.ID == "" || seen[e.ID] {
				t.Fatalf("entry id %q empty or repeated", e.ID)
			}
			seen[e.ID] = true
			class, _ := e.Classify()
			switch class {
			case ClassLocal, ClassHosted, ClassUnsupported:
			default:
				t.Fatalf("entry %q class %q", e.ID, class)
			}
			d, err := DraftImport(c, e.ID, ImportOptions{})
			if err != nil {
				t.Fatalf("draft of %q: %v", e.ID, err)
			}
			if p := d.Proposal; p != nil && (shell.MatchString(p.Name) || shell.MatchString(p.Version) || shell.MatchString(p.Command)) {
				t.Fatalf("proposal of %q carries shell syntax: %+v", e.ID, p)
			}
			if g := GatewayName(e.ID); len(g) > 63 || !strings.HasPrefix(g, "smcp-") {
				t.Fatalf("gateway name %q", g)
			}
		}
	})
}
