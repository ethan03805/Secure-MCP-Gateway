package cfharness

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// A local catalog entry for the harness: "loc-md", whose install text names
// the PyPI package markitdown-mcp, served at version 0.0.1 by a fake PyPI
// index as a wheel holding a small stdio MCP server with one tool,
// convert_to_markdown. Its import builds a local package through
// packaging, as FR-22.6 states.

// LocalEntryID is the ID of the harness's local catalog entry.
const LocalEntryID = "loc-md"

const localCatalogEntry = `  - id: loc-md
    name: loc-md
    provider: Example
    auth_type: Open
    repo: https://github.com/example/markitdown-mcp
    install: "uvx markitdown-mcp"
    description: A local fixture.
`

const localServer = `import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if "id" not in m:
        continue
    if m.get("method") == "initialize":
        out = {"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "md", "version": "1"}}}
    elif m.get("method") == "tools/list":
        out = {"jsonrpc": "2.0", "id": m["id"], "result": {"tools": [{"name": "convert_to_markdown", "description": "Convert a URI.", "inputSchema": {"type": "object"}}]}}
    elif m.get("method") == "tools/call":
        out = {"jsonrpc": "2.0", "id": m["id"], "result": {"content": [{"type": "text", "text": "converted by the local server"}]}}
    else:
        out = {"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "method not found"}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
`

func localWheel() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{
		{"markitdown_mcp/__init__.py", ""},
		{"markitdown_mcp/__main__.py", localServer},
		{"markitdown_mcp-0.0.1.dist-info/METADATA", "Metadata-Version: 2.1\nName: markitdown-mcp\nVersion: 0.0.1\n"},
	} {
		w, _ := zw.Create(f.name)
		_, _ = w.Write([]byte(f.body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

// pypi serves the wheel as a PyPI JSON API and file host.
func (e *Env) pypi() string {
	whl := localWheel()
	e.wheel = whl
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/pypi/markitdown-mcp/0.0.1/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"urls": []any{
			map[string]any{"filename": "markitdown_mcp-0.0.1-py3-none-any.whl", "url": srv.URL + "/files/markitdown_mcp-0.0.1-py3-none-any.whl",
				"packagetype": "bdist_wheel", "digests": map[string]string{"sha256": packaging.SHA256Hex(whl)}},
			map[string]any{"filename": "markitdown_mcp-0.0.1.tar.gz", "url": srv.URL + "/files/markitdown_mcp-0.0.1.tar.gz",
				"packagetype": "sdist", "digests": map[string]string{"sha256": packaging.SHA256Hex([]byte("sdist"))}},
		}})
	})
	mux.HandleFunc("/files/markitdown_mcp-0.0.1-py3-none-any.whl", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(whl) })
	srv = httptest.NewServer(mux)
	e.t.Cleanup(srv.Close)
	return srv.URL
}

// ProposeLocalEntry imports the local entry with the operator's exact pin
// and waits for the probe; it does not decide.
func (e *Env) ProposeLocalEntry() connector.ProposalView {
	e.t.Helper()
	in := connector.LocalImport{ArtifactType: "pypi", Package: "markitdown-mcp", Argv: []string{"python3", "-m", "markitdown_mcp"}, Licenses: []string{"MIT"},
		Version: "0.0.1", ArtifactSHA256: packaging.SHA256Hex(e.wheel)}
	p, err := e.Conn.ProposeLocal(e.localID, in, "op")
	if err != nil {
		e.t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for p.State == "building" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		p, _ = e.Conn.Proposal(p.ID)
	}
	if p.State != "ready" {
		e.t.Fatalf("local import: %s %s %s", p.State, p.ReasonCode, p.Error)
	}
	return p
}

// ImportLocalEntry imports and accepts the local entry; the revision stays
// verified-disabled.
func (e *Env) ImportLocalEntry() library.Revision {
	e.t.Helper()
	p := e.ProposeLocalEntry()
	got, err := e.Conn.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil {
		e.t.Fatal(err)
	}
	r, ok := e.Lib.Get(got.ServerID, got.Revision)
	if !ok {
		e.t.Fatalf("revision %s@%s not in the library", got.ServerID, got.Revision)
	}
	return r
}
