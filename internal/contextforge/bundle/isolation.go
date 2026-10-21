package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

// ReasonScopeBroken: a package token reached another package's tools or an
// admin route of the bundled instance (FR-22.29).
const ReasonScopeBroken = "CONTEXTFORGE_SCOPE_BROKEN"

// UserDomain is the reserved domain of the per-package users; ContextForge
// validates user addresses and refuses .invalid (FR-22.29).
const UserDomain = "example.com"

// PackageSpec is one hosted package to register (FR-22.34).
type PackageSpec struct {
	// Slug is the gateway name and slug recorded in the manifest's
	// upstream member (FR-22.10); it also names the team and the user.
	Slug string
	// URL is the package's E-18 endpoint as the instance reaches it.
	URL string
	// Transport is STREAMABLEHTTP or SSE.
	Transport string
}

// Provisioned is the ContextForge state of one hosted package. Token is
// the package-scoped token (a secret); the user password stays in the
// vault and is not held here.
type Provisioned struct {
	Slug      string    `json:"slug"`
	UserEmail string    `json:"user_email"`
	TeamID    string    `json:"team_id"`
	GatewayID string    `json:"gateway_id"`
	ServerID  string    `json:"server_id"`
	ToolIDs   []string  `json:"tool_ids"`
	Tools     []string  `json:"tools"` // served names, <slug>-<name>
	TokenID   string    `json:"token_id"`
	Expires   time.Time `json:"token_expires"`
	Token     string    `json:"-"`
}

// UserEmail is the address of a package's ContextForge user.
func UserEmail(slug string) string { return slug + "@" + UserDomain }

// Provision creates, for one hosted package, a team, a non-admin user who
// becomes the team's only member, the gateway and the virtual server with
// team visibility in that team at creation, and a token owned by the user
// for that team and server, valid one day (FR-22.29, FR-22.34). The
// administrator token is used only on these admin routes; it leaves the
// team once the objects exist.
func (a *Admin) Provision(ctx context.Context, spec PackageSpec, password string) (*Provisioned, error) {
	p := &Provisioned{Slug: spec.Slug, UserEmail: UserEmail(spec.Slug)}
	if err := a.EnsureUser(ctx, p.UserEmail, password, "Secure MCP Gateway package "+spec.Slug); err != nil {
		return nil, err
	}
	var team struct {
		ID string `json:"id"`
	}
	if err := a.Call(ctx, http.MethodPost, "/v1/teams", "", map[string]any{"name": spec.Slug, "description": "Secure MCP Gateway hosted package", "visibility": "private"}, &team); err != nil {
		return nil, err
	}
	p.TeamID = team.ID
	if err := a.Call(ctx, http.MethodPost, "/v1/teams/"+pathEscape(p.TeamID)+"/members", "", map[string]any{"email": p.UserEmail, "role": "owner"}, nil); err != nil {
		return nil, err
	}
	transport := spec.Transport
	if transport == "" {
		transport = "STREAMABLEHTTP"
	}
	var gw struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	if err := a.Call(ctx, http.MethodPost, "/v1/gateways", "", map[string]any{"name": spec.Slug, "url": spec.URL, "transport": transport,
		"team_id": p.TeamID, "visibility": "team"}, &gw); err != nil {
		return nil, err
	}
	if gw.Slug != spec.Slug {
		return nil, fmt.Errorf("contextforge gave gateway %s the slug %q, not %q", spec.Slug, gw.Slug, spec.Slug)
	}
	p.GatewayID = gw.ID
	tools, err := a.Tools(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, t := range tools {
		if t.GatewayID == p.GatewayID {
			p.ToolIDs = append(p.ToolIDs, t.ID)
			p.Tools = append(p.Tools, t.Name)
		}
	}
	sort.Strings(p.Tools)
	var srv struct {
		ID string `json:"id"`
	}
	if err := a.Call(ctx, http.MethodPost, "/v1/servers", "", map[string]any{"server": map[string]any{"name": spec.Slug, "associated_tools": p.ToolIDs},
		"team_id": p.TeamID, "visibility": "team"}, &srv); err != nil {
		return nil, err
	}
	p.ServerID = srv.ID
	if err := a.Call(ctx, http.MethodDelete, "/v1/teams/"+pathEscape(p.TeamID)+"/members/"+pathEscape(AdminEmail), "", nil, nil); err != nil {
		return nil, err
	}
	if err := a.RenewToken(ctx, p, password); err != nil {
		return nil, err
	}
	return p, nil
}

// RenewToken mints a new package token owned by the package's user for
// its team and virtual server, valid one day (FR-22.29).
func (a *Admin) RenewToken(ctx context.Context, p *Provisioned, password string) error {
	session, err := a.Login(ctx, p.UserEmail, password)
	if err != nil {
		return err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Token       struct {
			ID        string `json:"id"`
			ExpiresAt string `json:"expires_at"`
		} `json:"token"`
	}
	// The name is unique per user: a probe's token and the token of the
	// registration that follows it can be minted within the same second.
	now := time.Now().UTC()
	if err := a.Call(ctx, http.MethodPost, "/v1/tokens", session, map[string]any{"name": fmt.Sprintf("%s-%s-%09d", p.Slug, now.Format("20060102T150405"), now.Nanosecond()),
		"expires_in_days": 1, "team_id": p.TeamID, "scope": map[string]any{"server_id": p.ServerID}}, &tok); err != nil {
		return err
	}
	if tok.AccessToken == "" {
		return fmt.Errorf("contextforge minted no token for %s", p.Slug)
	}
	p.Token, p.TokenID = tok.AccessToken, tok.Token.ID
	if t, err := time.Parse("2006-01-02T15:04:05.999999", tok.Token.ExpiresAt); err == nil {
		p.Expires = t.UTC()
	}
	return nil
}

// Tool is one tool as the admin API lists it.
type Tool struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	GatewayID   string `json:"gatewayId"`
	GatewaySlug string `json:"gatewaySlug"`
	TeamID      string `json:"teamId"`
	Visibility  string `json:"visibility"`
	Description string `json:"description"`
}

// Tools lists the tools a token sees (the administrator's when token is
// "").
func (a *Admin) Tools(ctx context.Context, token string) ([]Tool, error) {
	var out []Tool
	err := a.Call(ctx, http.MethodGet, "/v1/tools?include_inactive=true", token, nil, &out)
	return out, err
}

// Finding is one way a package token reached beyond its package.
type Finding struct {
	Package string `json:"package"`
	Probe   string `json:"probe"`
	Detail  string `json:"detail"`
}

// SelfCheck is the scope self-check of FR-22.29: with each package's
// token it lists tools on the global /mcp and /rpc endpoints, calls a tool
// of every other package through that package's /servers/<id>/mcp and
// /servers/<id>/sse and through /mcp and /rpc, and requests an admin
// route. Every listed tool of another package, every call that is not
// refused, and an admin route that accepts the token is a finding.
func (a *Admin) SelfCheck(ctx context.Context, pkgs []*Provisioned) []Finding {
	var out []Finding
	owner := map[string]string{}
	for _, p := range pkgs {
		for _, t := range p.Tools {
			owner[t] = p.Slug
		}
	}
	for _, p := range pkgs {
		add := func(probe, format string, args ...any) {
			out = append(out, Finding{Package: p.Slug, Probe: probe, Detail: fmt.Sprintf(format, args...)})
		}
		for _, ep := range []string{"/mcp", "/rpc"} {
			names, status, err := a.listTools(ctx, ep, p.Token)
			if err != nil || status != http.StatusOK {
				continue // refused: nothing listed
			}
			for _, n := range names {
				if o, ok := owner[n]; ok && o != p.Slug {
					add("tools/list "+ep, "lists %s of package %s", n, o)
				} else if !ok && !slices.Contains(p.Tools, n) {
					add("tools/list "+ep, "lists %s, which no hosted package registered", n)
				}
			}
		}
		for _, q := range pkgs {
			if q == p || len(q.Tools) == 0 {
				continue
			}
			tool := q.Tools[0]
			for _, ep := range []string{"/servers/" + q.ServerID + "/mcp", "/mcp", "/rpc"} {
				if reached, why := a.callReaches(ctx, ep, p.Token, tool); reached {
					add("tools/call "+ep, "called %s of package %s: %s", tool, q.Slug, why)
				}
			}
			if st := a.status(ctx, http.MethodGet, "/servers/"+q.ServerID+"/sse", p.Token); st == http.StatusOK {
				add("GET /servers/"+q.ServerID+"/sse", "opened the SSE stream of package %s", q.Slug)
			}
		}
		for _, route := range []string{"/v1/auth/email/admin/users", "/v1/tokens/admin/all"} {
			if st := a.status(ctx, http.MethodGet, route, p.Token); st >= 200 && st < 300 {
				add("GET "+route, "admin route accepted the package token (HTTP %d)", st)
			}
		}
	}
	return out
}

// rpc sends one JSON-RPC request and returns the HTTP status and body.
func (a *Admin) rpc(ctx context.Context, path, token, method string, params any) (int, []byte, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	req.Header.Set("Authorization", "Bearer "+token)
	c := a.HTTP
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, sseData(raw), err
}

// sseData returns the JSON of the first event of an event-stream body, or
// the body itself.
func sseData(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("data:")) || bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return raw
	}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if d, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:")); ok {
			return bytes.TrimSpace(d)
		}
	}
	return raw
}

func (a *Admin) listTools(ctx context.Context, path, token string) ([]string, int, error) {
	st, raw, err := a.rpc(ctx, path, token, "tools/list", map[string]any{})
	if err != nil || st != http.StatusOK {
		return nil, st, err
	}
	var r struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, st, err
	}
	var out []string
	for _, t := range r.Result.Tools {
		out = append(out, t.Name)
	}
	return out, st, nil
}

// callReaches reports whether a tools/call was not refused: it is refused
// by HTTP 401, 403 or 404, a JSON-RPC error, or a result with isError
// whose text begins "Unknown tool" (FR-22.33).
func (a *Admin) callReaches(ctx context.Context, path, token, tool string) (bool, string) {
	st, raw, err := a.rpc(ctx, path, token, "tools/call", map[string]any{"name": tool, "arguments": map[string]any{}})
	if err != nil {
		return false, ""
	}
	if st != http.StatusOK {
		return false, ""
	}
	var r struct {
		Error  *json.RawMessage `json:"error"`
		Result *struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Error != nil || r.Result == nil {
		return false, ""
	}
	if r.Result.IsError && len(r.Result.Content) > 0 && strings.HasPrefix(r.Result.Content[0].Text, "Unknown tool") {
		return false, ""
	}
	text := ""
	if len(r.Result.Content) > 0 {
		text = r.Result.Content[0].Text
	}
	if len(text) > 120 {
		text = text[:120]
	}
	return true, fmt.Sprintf("result (isError %v) %q", r.Result.IsError, text)
}

func (a *Admin) status(ctx context.Context, method, path, token string) int {
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return 0 // an SSE stream that stays open times out: counted below
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
