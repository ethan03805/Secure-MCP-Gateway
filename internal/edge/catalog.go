package edge

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// serverFor returns the session's mcp.Server, building it on first use or
// after a policy revision change (SR-5.7-1). Without a snapshot it returns
// an empty server and caches nothing; mcpChain has already refused the
// request in that state, so this only covers a snapshot removed between the
// two checks.
func (g *Gateway) serverFor(r *http.Request) *mcp.Server {
	sess, _ := r.Context().Value(ctxSession).(*session.Session)
	snap := g.decider.Snapshot()
	if sess == nil || snap == nil {
		return g.emptyServer(nil)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if ss := g.servers[sess.ID]; ss != nil && ss.revision == snap.Revision {
		return ss.srv
	}
	if !g.store.IsActive(sess.ID) {
		return g.emptyServer(nil)
	}
	srv := g.buildServer(sess, snap)
	g.servers[sess.ID] = &sessionServer{revision: snap.Revision, srv: srv}
	return srv
}

func (g *Gateway) serverOptions() *mcp.ServerOptions {
	return &mcp.ServerOptions{
		SupportedProtocolVersions: ProtocolVersions,
		PageSize:                  g.cfg.Limits.CatalogPageSize, // CP-19
		Capabilities:              &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}},
		SetCacheable: func(ctx context.Context, req mcp.Request, c *mcp.Cacheable) { // FR-1.13
			c.TTLMs = g.cfg.Limits.CatalogTTLMs
			c.CacheScope = "private"
		},
		Logger: g.log,
	}
}

func (g *Gateway) emptyServer(catalog map[string]bool) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "secure-mcp-gateway", Version: backend.Version}, g.serverOptions())
	srv.AddReceivingMiddleware(g.methodGate(catalog))
	return srv
}

// buildServer creates the per-session catalog (FR-1.26, FR-1.28, FR-1.50,
// SR-5.4-1). Tool definitions come from the registry's ManifestSource:
// verified manifests once E-13 provides them, the live list until then.
func (g *Gateway) buildServer(sess *session.Session, snap *policy.Snapshot) *mcp.Server {
	catalog := map[string]bool{}
	srv := g.emptyServer(catalog)
	for _, gr := range snap.Grants(sess.Template) {
		ref := g.reg.Resolve(backend.PublicName(gr.Server, gr.Tool))
		if ref == nil {
			continue // policy names a tool no enabled server provides
		}
		catalog[ref.Public] = true
		t := &mcp.Tool{
			Name:        ref.Public,
			Title:       ref.Tool.Title,
			Description: ref.Tool.Description,
			InputSchema: stripHeaderAnnotations(ref.Tool.InputSchema),
			Annotations: ref.Tool.Annotations,
		}
		if ref.Tool.OutputSchema != nil {
			t.OutputSchema = ref.Tool.OutputSchema
		}
		if gr.Rule.Approval { // FR-1.50
			t.Meta = mcp.Meta{MetaRequiresUserInteraction: true, MetaApprovalRequired: true}
		}
		srv.AddTool(t, g.toolHandler(*sess, ref))
	}
	return srv
}

// stripHeaderAnnotations removes x-mcp-header from a presented schema (FR-1.28).
func stripHeaderAnnotations(schema any) any {
	raw, err := json.Marshal(schema)
	if err != nil {
		return schema
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return schema
	}
	if props, ok := m["properties"].(map[string]any); ok {
		for _, p := range props {
			if pm, ok := p.(map[string]any); ok {
				delete(pm, "x-mcp-header")
			}
		}
	}
	return m
}

// Northbound methods of the baseline profile (FR-1.11) plus the legacy
// handshake (FR-1.46) and ping.
var allowedMethods = map[string]bool{
	"server/discover": true, "tools/list": true, "tools/call": true, "subscriptions/listen": true,
	"initialize": true, "notifications/initialized": true, "ping": true, "notifications/cancelled": true,
}

// methodGate rejects unqualified methods (FR-1.10, FR-1.42) and answers a
// call to a tool outside the session catalog with the FR-1.30 message.
func (g *Gateway) methodGate(catalog map[string]bool) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if !allowedMethods[method] {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not available: " + method}
			}
			if method == "tools/call" {
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && !catalog[p.Name] {
					return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "Unknown tool"}
				}
			}
			return next(ctx, method, req)
		}
	}
}
