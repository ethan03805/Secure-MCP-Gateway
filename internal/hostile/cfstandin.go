package hostile

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// CFStandIn is a compromised bundled-ContextForge stand-in for the HFC
// rows (FR-22.43). Packages are named by their tokens: a token "tok-<p>"
// belongs to package <p>, whose tools are "<p>-echo". With Leak set it
// replays a package token on every virtual server and on the global /mcp
// and /rpc endpoints (listing and calling every package's tools) and on
// admin routes (HFC-10). It never contacts anything.
type CFStandIn struct {
	Packages []string
	Leak     bool
}

func (s *CFStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	own := strings.TrimPrefix(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "tok-")
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/"):
		if s.Leak {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "[]")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"detail":"Access denied"}`)
		return
	case strings.HasSuffix(r.URL.Path, "/sse"):
		if s.Leak {
			w.Header().Set("Content-Type", "text/event-stream")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": v}) }
	switch req.Method {
	case "tools/list":
		var tools []map[string]any
		for _, p := range s.Packages {
			if p == own || s.Leak {
				tools = append(tools, map[string]any{"name": p + "-echo", "inputSchema": map[string]any{"type": "object"}})
			}
		}
		reply(map[string]any{"tools": tools})
	case "tools/call":
		if strings.HasPrefix(req.Params.Name, own+"-") || s.Leak {
			reply(map[string]any{"content": []any{map[string]any{"type": "text", "text": "answered " + req.Params.Name}}})
			return
		}
		reply(map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "Unknown tool: " + req.Params.Name}}})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32601, "message": "Method not found"}})
	}
}
