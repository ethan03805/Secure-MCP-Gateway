package connector

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// fakeVirtualServer answers newline-delimited JSON-RPC as a ContextForge
// virtual server would: its tools carry the gateway slug, and a tool it no
// longer serves gets an "Unknown tool" isError result.
type fakeVirtualServer struct {
	inR  *io.PipeReader
	inW  *io.PipeWriter
	outR *io.PipeReader
	outW *io.PipeWriter
	mu   sync.Mutex
	seen []string
}

func newFakeVirtualServer() *fakeVirtualServer {
	f := &fakeVirtualServer{}
	f.inR, f.inW = io.Pipe()
	f.outR, f.outW = io.Pipe()
	go func() {
		sc := bufio.NewScanner(f.inR)
		for sc.Scan() {
			var m struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			_ = json.Unmarshal(sc.Bytes(), &m)
			var res any
			switch m.Method {
			case "tools/list":
				res = map[string]any{"tools": []any{map[string]any{"name": "smcp-x-get-time", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "smcp-x-added"}}}
			case "tools/call":
				f.mu.Lock()
				f.seen = append(f.seen, m.Params.Name)
				f.mu.Unlock()
				if m.Params.Name == "smcp-x-get-time" {
					res = map[string]any{"content": []any{map[string]any{"type": "text", "text": "12:00"}}}
				} else {
					res = map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "Unknown tool: " + m.Params.Name}}}
				}
			}
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": res})
			_, _ = f.outW.Write(append(out, '\n'))
		}
	}()
	return f
}

func (f *fakeVirtualServer) Read(p []byte) (int, error)  { return f.outR.Read(p) }
func (f *fakeVirtualServer) Write(p []byte) (int, error) { return f.inW.Write(p) }
func (f *fakeVirtualServer) Close() error                { _ = f.inW.Close(); return f.outW.Close() }
func (f *fakeVirtualServer) Stderr() string              { return "" }

// FR-22.10 (dispatch part) and FR-22.33 (E-10 part): a call goes out under
// the backend name, the served list comes back under manifest names, and
// an "Unknown tool" result for a manifest tool becomes a -32601 error (the
// Gateway's -31007 BACKEND_ERROR with backendCode -32601) and starts a
// reconciliation.
func TestHostedProcessRenames(t *testing.T) {
	reqtest.Partial(t, "FR-22.10", "FR-22.33")
	f := newFakeVirtualServer()
	var unknown []string
	p := renameProcess(f, map[string]string{"get_time": "smcp-x-get-time", "gone": "smcp-x-gone"}, func(tool string) { unknown = append(unknown, tool) })
	defer p.Close()
	r := bufio.NewReader(p)
	ask := func(req string) map[string]any {
		t.Helper()
		// Written in two pieces: the wrapper must wait for the line's end.
		if _, err := p.Write([]byte(req[:10])); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Write([]byte(req[10:] + "\n")); err != nil {
			t.Fatal(err)
		}
		line, err := r.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		return m
	}
	list := ask(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	tools := list["result"].(map[string]any)["tools"].([]any)
	if tools[0].(map[string]any)["name"] != "get_time" || tools[1].(map[string]any)["name"] != "smcp-x-added" {
		t.Fatalf("list %v", tools)
	}
	ok := ask(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_time","arguments":{}}}`)
	if ok["result"] == nil {
		t.Fatalf("call %v", ok)
	}
	gone := ask(`{"jsonrpc":"2.0","id":"3","method":"tools/call","params":{"name":"gone","arguments":{}}}`)
	e, _ := gone["error"].(map[string]any)
	if e == nil || e["code"].(float64) != -32601 || gone["id"] != "3" || gone["result"] != nil {
		t.Fatalf("unknown tool %v", gone)
	}
	if strings.Join(unknown, ",") != "gone" {
		t.Fatalf("reconciliation triggers %v", unknown)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.seen, ",") != "smcp-x-get-time,smcp-x-gone" {
		t.Fatalf("backend names sent %v", f.seen)
	}
}
