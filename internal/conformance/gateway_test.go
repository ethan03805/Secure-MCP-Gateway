package conformance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// alias is the backend's server alias; public names are alias_<tool>.
const alias = "s"

// gateway is a running Gateway with one session.
type gateway struct {
	t     *testing.T
	app   *app.App
	url   string
	http  *http.Client
	token string
}

func startGateway(t *testing.T, b *scripted) *gateway {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	hash, err := keys.HashPassword("admin password 12")
	if err != nil {
		t.Fatal(err)
	}
	port, adminPort := gwtest.FreePort(t), gwtest.FreePort(t)
	toml := fmt.Sprintf(`
[listener]
address = "127.0.0.1:%d"
public_url = "https://127.0.0.1:%d"
[admin_listener]
address = "127.0.0.1:%d"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[approvals]
notify = "off"
[policy]
file = "policy.json"
[filters.content_types]
allow = ["image/png", "audio/wav"]
[limits]
upstream_timeout = "5s"
client_deadline = "6s"
principal_calls_per_minute = 100000
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[server]]
alias = %q
command = "/conformance/backend"
`, port, port, adminPort, stateDir, hash, alias)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	tools, _ := json.Marshal(b.names())
	pol := fmt.Sprintf(`{"revision": "r1", "framework_profiles": {"dev": {"templates": ["all"], "default_template": "all"}},
  "templates": {"all": {"rules": [{"id": "all", "server": %q, "tools": %s}]}}}`, alias, tools)
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), JanitorInterval: time.Second,
		Launcher: pipeline.InProcessLauncher{Raw: map[string]func(context.Context, io.Reader, io.Writer) error{"/conformance/backend": b.serve}}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- a.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
		}
		a.Close()
	})
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(stateDir, keys.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(ca)
	_, tok, err := a.Store.Create(session.CreateParams{PrincipalID: "cc", ClientID: "conformance", Listener: "tls", Claims: session.Claims{Template: "all"}})
	if err != nil {
		t.Fatal(err)
	}
	return &gateway{t: t, app: a, url: cfg.ResourceURI(), token: tok.Access,
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}}
}

// public is the presented name of a backend tool.
func public(tool string) string { return backend.PublicName(alias, tool) }

// headersFor derives the 2026-07-28 request headers from a message.
func headersFor(msg map[string]any) map[string]string {
	h := map[string]string{}
	params, _ := msg["params"].(map[string]any)
	meta, _ := params["_meta"].(map[string]any)
	if v, ok := meta["io.modelcontextprotocol/protocolVersion"].(string); ok {
		h["MCP-Protocol-Version"] = v
	}
	if m, ok := msg["method"].(string); ok {
		h["Mcp-Method"] = m
	}
	if n, ok := params["name"].(string); ok {
		h["Mcp-Name"] = n
	} else if u, ok := params["uri"].(string); ok {
		h["Mcp-Name"] = u
	}
	return h
}

// response is one HTTP answer: its status, content type and the JSON-RPC
// messages it carried (the body, or each event's data).
type response struct {
	Status      int
	ContentType string
	Messages    []json.RawMessage
	Body        string
}

// post sends a raw body with headers (the session's bearer is added).
func (g *gateway) post(body []byte, hdr map[string]string) response {
	g.t.Helper()
	req, err := http.NewRequest("POST", g.url, strings.NewReader(string(body)))
	if err != nil {
		g.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+g.token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := response{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: string(raw)}
	if strings.HasPrefix(r.ContentType, "text/event-stream") {
		for _, line := range strings.Split(string(raw), "\n") {
			if d, ok := strings.CutPrefix(line, "data:"); ok {
				r.Messages = append(r.Messages, json.RawMessage(strings.TrimSpace(d)))
			}
		}
	} else if len(strings.TrimSpace(string(raw))) > 0 && json.Valid(raw) {
		r.Messages = append(r.Messages, json.RawMessage(raw))
	}
	return r
}

// send posts a message with the headers it implies.
func (g *gateway) send(msg map[string]any) response {
	g.t.Helper()
	raw, err := json.Marshal(msg)
	if err != nil {
		g.t.Fatal(err)
	}
	return g.post(raw, headersFor(msg))
}

// last is the final JSON-RPC message of a response decoded as a map.
func (r response) last() map[string]any {
	if len(r.Messages) == 0 {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(r.Messages[len(r.Messages)-1], &m)
	return m
}

// errorCode returns the JSON-RPC error code of a message, or 0.
func errorCode(m map[string]any) int {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return int(c)
}
