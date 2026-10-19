package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ServedTool is one tool definition a virtual server lists.
type ServedTool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// ServedTools reads tools/list of a package's virtual server with its own
// token: the tool definitions as the Gateway will be served them.
func (a *Admin) ServedTools(ctx context.Context, p *Provisioned) ([]ServedTool, error) {
	st, raw, err := a.rpc(ctx, "/servers/"+p.ServerID+"/mcp", p.Token, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("contextforge tools/list of %s: HTTP %d", p.Slug, st)
	}
	var r struct {
		Result *struct {
			Tools []ServedTool `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("contextforge tools/list of %s: %w", p.Slug, err)
	}
	if r.Error != nil || r.Result == nil {
		return nil, fmt.Errorf("contextforge tools/list of %s was refused", p.Slug)
	}
	return r.Result.Tools, nil
}

// Deprovision removes a package's token, virtual server, gateway (with
// its tools), team and user, ignoring objects already gone. The probe of
// a hosted entry uses it, so that the registration of the enabled package
// can reuse the gateway name fixed at the probe.
func (a *Admin) Deprovision(ctx context.Context, p *Provisioned) error {
	var first error
	del := func(path string) {
		err := a.Call(ctx, http.MethodDelete, path, "", nil, nil)
		var api *APIError
		if err != nil && (!asAPI(err, &api) || api.Status != http.StatusNotFound) && first == nil {
			first = err
		}
	}
	if p.TokenID != "" {
		del("/v1/tokens/admin/" + pathEscape(p.TokenID))
	}
	if p.ServerID != "" {
		del("/v1/servers/" + pathEscape(p.ServerID))
	}
	if p.GatewayID != "" {
		del("/v1/gateways/" + pathEscape(p.GatewayID))
	}
	if p.TeamID != "" {
		del("/v1/teams/" + pathEscape(p.TeamID))
	}
	if p.UserEmail != "" {
		del("/v1/auth/email/admin/users/" + pathEscape(p.UserEmail))
	}
	return first
}
