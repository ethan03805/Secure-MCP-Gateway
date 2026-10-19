package adapter_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
)

// cfLikeServer is a stand-in for a ContextForge virtual-server endpoint:
// a stateless Streamable HTTP MCP server behind a bearer check that answers
// a refused token with HTTP 403 and a non-JSON-RPC {"detail": ...} body, as
// ContextForge v1.0.11 does, and offers a tool whose name carries the
// gateway slug and hyphens.
func cfLikeServer(t *testing.T, token string, sse bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-streamable-http", Version: ""}, nil)
	type in struct {
		Timezone string `json:"timezone,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "fast-time-get-system-time", Description: "Get current system time"},
		func(_ context.Context, _ *mcp.CallToolRequest, a in) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "time in " + a.Timezone}}}, nil, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: !sse})
	var refused atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			refused.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"detail":"Access denied"}`)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &refused
}

func TestUpstreamRelayToContextForgeLikeServer(t *testing.T) {
	for _, sse := range []bool{false, true} {
		name := "json"
		if sse {
			name = "sse"
		}
		t.Run(name, func(t *testing.T) {
			srv, refused := cfLikeServer(t, "pkg-token", sse)
			t.Setenv(adapter.UpstreamTokenEnv, "pkg-token")
			t.Setenv(adapter.UpstreamTokenFileEnv, "")
			cs := pipeClient(t, func(in io.Reader, out io.Writer) {
				adapter.StdioMain([]string{"--experimental-upstream", srv.URL + "/servers/abc/mcp"}, in, out, io.Discard)
			})
			tools, err := cs.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(tools.Tools) != 1 || tools.Tools[0].Name != "fast-time-get-system-time" {
				t.Fatalf("tools %+v", tools.Tools)
			}
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "fast-time-get-system-time", Arguments: map[string]any{"timezone": "UTC"}})
			if err != nil {
				t.Fatal(err)
			}
			if txt := res.Content[0].(*mcp.TextContent).Text; txt != "time in UTC" {
				t.Fatalf("result %q", txt)
			}
			if refused.Load() != 0 {
				t.Fatalf("%d requests without the token", refused.Load())
			}
		})
	}
}

// A refused token scope (HTTP 403 with a body that is not JSON-RPC) becomes
// a JSON-RPC error for the request instead of an unmatched message.
func TestUpstreamRelayRefusedScope(t *testing.T) {
	srv, _ := cfLikeServer(t, "right", false)
	var out bytes.Buffer
	r := &adapter.Relay{URL: srv.URL + "/mcp", HTTP: srv.Client(), Tokens: adapter.StaticToken("wrong"), Upstream: true,
		In: strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}` + "\n"), Out: &out}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `"id":7`) || !strings.Contains(got, `"code":-32000`) || !strings.Contains(got, "upstream answered HTTP 403") || strings.Contains(got, `{"detail"`) {
		t.Fatalf("relayed %s", got)
	}
}

func TestUpstreamRelay401NotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	var out bytes.Buffer
	r := &adapter.Relay{URL: srv.URL + "/mcp", HTTP: srv.Client(), Tokens: adapter.StaticToken("t"), Upstream: true,
		In: strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"), Out: &out}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || !strings.Contains(out.String(), "upstream refused the token") {
		t.Fatalf("hits %d out %s", hits.Load(), out.String())
	}
}

func TestUpstreamRedirectNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	t.Setenv(adapter.UpstreamTokenEnv, "t")
	t.Setenv(adapter.UpstreamTokenFileEnv, "")
	var out, errb bytes.Buffer
	code := adapter.StdioMain([]string{"--experimental-upstream", srv.URL + "/mcp"},
		strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n"), &out, &errb)
	if code != 0 || elsewhere.Load() != 0 || !strings.Contains(out.String(), "HTTP 307") {
		t.Fatalf("code %d redirected %d out %s err %s", code, elsewhere.Load(), out.String(), errb.String())
	}
}

func TestCheckUpstreamURL(t *testing.T) {
	ok := []string{"https://cf.example/servers/x/mcp", "http://127.0.0.1:4444/servers/x/mcp", "http://localhost:4444/mcp", "http://[::1]:4444/mcp"}
	bad := []string{"http://10.0.0.5:4444/mcp", "http://cf.example/mcp", "ftp://127.0.0.1/x", "https://user:pw@cf.example/mcp", "/servers/x/mcp", "https://cf.example/mcp#f", "http://127.0.0.1.nip.io/mcp"}
	for _, u := range ok {
		if _, err := adapter.CheckUpstreamURL(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := adapter.CheckUpstreamURL(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestUpstreamToken(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tok")
	if err := os.WriteFile(file, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if tok, err := adapter.UpstreamToken(env(map[string]string{adapter.UpstreamTokenEnv: "env-token"})); err != nil || tok != "env-token" {
		t.Fatalf("env: %q %v", tok, err)
	}
	if tok, err := adapter.UpstreamToken(env(map[string]string{adapter.UpstreamTokenFileEnv: file})); err != nil || tok != "file-token" {
		t.Fatalf("file: %q %v", tok, err)
	}
	for name, m := range map[string]map[string]string{
		"none":    {},
		"both":    {adapter.UpstreamTokenEnv: "a", adapter.UpstreamTokenFileEnv: file},
		"empty":   {adapter.UpstreamTokenFileEnv: empty},
		"missing": {adapter.UpstreamTokenFileEnv: filepath.Join(dir, "nope")},
	} {
		if _, err := adapter.UpstreamToken(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUpstreamFlagRefusesWithoutToken(t *testing.T) {
	t.Setenv(adapter.UpstreamTokenEnv, "")
	t.Setenv(adapter.UpstreamTokenFileEnv, "")
	var out, errb bytes.Buffer
	if code := adapter.StdioMain([]string{"--experimental-upstream", "http://127.0.0.1:1/mcp"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), adapter.UpstreamTokenEnv) {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if code := adapter.StdioMain([]string{"--experimental-upstream", "http://192.0.2.1/mcp"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("off-host http accepted: %d", code)
	}
}
