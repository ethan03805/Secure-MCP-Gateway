package bundle

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// standIn is a compromised bundled-instance stand-in (HFC-10): it can
// accept a package token on an admin route, on another package's virtual
// server, and list another package's tools on /mcp.
type standIn struct {
	adminOpen, crossCall, crossList, unknownTool bool
}

func (s *standIn) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/"):
			if s.adminOpen {
				_, _ = io.WriteString(w, "[]")
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"detail":"Access denied"}`)
			return
		case strings.HasSuffix(r.URL.Path, "/sse"):
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		own := "a"
		if tok == "tok-b" {
			own = "b"
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			tools := []map[string]any{{"name": "pkg-" + own + "-echo"}}
			if s.crossList && own == "a" {
				tools = append(tools, map[string]any{"name": "pkg-b-echo"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": tools}})
		case "tools/call":
			if strings.HasPrefix(req.Params.Name, "pkg-"+own) || (s.crossCall && strings.HasPrefix(r.URL.Path, "/servers/")) {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "answer"}}}})
				return
			}
			if s.unknownTool {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "Unknown tool: " + req.Params.Name}}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32601, "message": "Tool not found"}})
		}
	})
}

// FR-22.29 and HFC-10 (self-check part): an isolated stand-in gives no
// finding (refusals as an Unknown tool result or -32601 count as refused);
// a stand-in that lists another package's tools, accepts a call on another
// package's virtual server, or opens an admin route to a package token is
// reported for each.
func TestSelfCheckFindings(t *testing.T) {
	reqtest.Partial(t, "FR-22.29")
	pkgs := func() []*Provisioned {
		return []*Provisioned{
			{Slug: "pkg-a", ServerID: "sa", Tools: []string{"pkg-a-echo"}, Token: "tok-a"},
			{Slug: "pkg-b", ServerID: "sb", Tools: []string{"pkg-b-echo"}, Token: "tok-b"},
		}
	}
	cases := []struct {
		name  string
		s     standIn
		probe string
	}{
		{"isolated", standIn{}, ""},
		{"isolated, unknown-tool results", standIn{unknownTool: true}, ""},
		{"cross list", standIn{crossList: true}, "tools/list /mcp"},
		{"cross call", standIn{crossCall: true}, "tools/call /servers/sb/mcp"},
		{"admin route", standIn{adminOpen: true}, "GET /v1/auth/email/admin/users"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(tc.s.handler())
		a := &Admin{Base: srv.URL, AdminToken: func() (string, error) { return "admin", nil }}
		f := a.SelfCheck(context.Background(), pkgs())
		srv.Close()
		if tc.probe == "" {
			if len(f) != 0 {
				t.Errorf("%s: findings %+v", tc.name, f)
			}
			continue
		}
		found := false
		for _, x := range f {
			if x.Probe == tc.probe {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no %q finding in %+v", tc.name, tc.probe, f)
		}
	}
}
