package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Drift is one difference between the bundled instance and the state the
// Connector derives from the registry and the manifests (FR-22.33). A
// drift with a Package suspends that hosted package revision; a removal
// is an object the Connector did not create and has deleted.
type Drift struct {
	Package string `json:"package,omitempty"`
	Kind    string `json:"kind"`
	Object  string `json:"object"`
	Detail  string `json:"detail"`
	Removed bool   `json:"removed,omitempty"`
}

// Expected is one enabled hosted package as the Connector registered it:
// its provisioned objects, the hosted URL its gateway must point at and
// the served tool names with their descriptions from the manifest.
type Expected struct {
	Provisioned
	URL   string            `json:"url"`
	Tools map[string]string `json:"expected_tools"` // backend_name -> description
}

// adminObject is the subset of a listed admin object reconciliation reads.
type adminObject struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	URL         string `json:"url"`
	TeamID      string `json:"teamId"`
	Visibility  string `json:"visibility"`
	GatewayID   string `json:"gatewayId"`
	Description string `json:"description"`
	Email       string `json:"email"`
	IsAdmin     bool   `json:"is_admin"`
	IsActive    bool   `json:"is_active"`
	IsPersonal  bool   `json:"is_personal"`
	// Tool IDs a virtual server holds.
	AssociatedTools []string `json:"associatedToolIds"`
}

// list reads a collection that ContextForge answers either as a bare list
// or wrapped in an object (paginated forms).
func (a *Admin) list(ctx context.Context, path string) ([]adminObject, error) {
	var raw json.RawMessage
	if err := a.Call(ctx, http.MethodGet, path, "", nil, &raw); err != nil {
		return nil, err
	}
	var out []adminObject
	if err := json.Unmarshal(raw, &out); err == nil {
		return out, nil
	}
	var wrapped map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("contextforge %s: %w", path, err)
	}
	for _, k := range []string{"items", "data", "users", "teams", "tokens", "gateways", "servers"} {
		if v, ok := wrapped[k]; ok {
			if err := json.Unmarshal(v, &out); err == nil {
				return out, nil
			}
		}
	}
	return nil, fmt.Errorf("contextforge %s: unexpected list shape", path)
}

// Reconcile compares the instance's admin state with exp, deletes every
// gateway, virtual server, user, team, prompt, resource and A2A agent the
// Connector did not create (FR-22.33, FR-22.38), and reports drift of the
// expected objects: the gateway's name, slug, URL, team or visibility, the
// virtual server's team, visibility or tools, and the served tools'
// names and descriptions. It never changes an expected object: a drifted
// package is suspended by the caller, not repaired.
func (a *Admin) Reconcile(ctx context.Context, exp []Expected) ([]Drift, error) {
	var out []Drift
	gateways, servers := map[string]*Expected{}, map[string]*Expected{}
	users, teams := map[string]bool{AdminEmail: true}, map[string]bool{}
	for i := range exp {
		e := &exp[i]
		gateways[e.GatewayID], servers[e.ServerID] = e, e
		users[e.UserEmail], teams[e.TeamID] = true, true
	}
	remove := func(kind, path, object, detail string) {
		d := Drift{Kind: kind, Object: object, Detail: detail, Removed: true}
		if err := a.Call(ctx, http.MethodDelete, path, "", nil, nil); err != nil {
			d.Removed, d.Detail = false, detail+"; removal failed: "+err.Error()
		}
		out = append(out, d)
	}
	gws, err := a.list(ctx, "/v1/gateways?include_inactive=true")
	if err != nil {
		return nil, err
	}
	seenGW := map[string]bool{}
	for _, g := range gws {
		e, ok := gateways[g.ID]
		if !ok {
			remove("unknown_gateway", "/v1/gateways/"+pathEscape(g.ID), "gateway "+g.Name, "a gateway the Connector did not register")
			continue
		}
		seenGW[g.ID] = true
		for _, c := range []struct{ field, got, want string }{
			{"name", g.Name, e.Slug}, {"slug", g.Slug, e.Slug}, {"url", g.URL, e.URL}, {"team", g.TeamID, e.TeamID}, {"visibility", g.Visibility, "team"},
		} {
			if c.got != c.want {
				out = append(out, Drift{Package: e.Slug, Kind: "gateway_" + c.field, Object: "gateway " + e.Slug, Detail: fmt.Sprintf("%s is %q, registered %q", c.field, c.got, c.want)})
			}
		}
	}
	for _, e := range exp {
		if !seenGW[e.GatewayID] {
			out = append(out, Drift{Package: e.Slug, Kind: "gateway_missing", Object: "gateway " + e.Slug, Detail: "the gateway is gone"})
		}
	}
	tools, err := a.Tools(ctx, "")
	if err != nil {
		return nil, err
	}
	served := map[string]map[string]string{}
	for _, t := range tools {
		if e, ok := gateways[t.GatewayID]; ok {
			if served[e.Slug] == nil {
				served[e.Slug] = map[string]string{}
			}
			served[e.Slug][t.Name] = t.Description
			if t.TeamID != e.TeamID || t.Visibility != "team" {
				out = append(out, Drift{Package: e.Slug, Kind: "tool_team", Object: "tool " + t.Name, Detail: fmt.Sprintf("team %q visibility %q", t.TeamID, t.Visibility)})
			}
		} else if !slices.ContainsFunc(gws, func(g adminObject) bool { return g.ID == t.GatewayID }) {
			// A tool of no gateway: REST or gRPC wrapping (FR-22.38).
			remove("unknown_tool", "/v1/tools/"+pathEscape(t.ID), "tool "+t.Name, "a tool the Connector did not register")
		}
	}
	for _, e := range exp {
		got := served[e.Slug]
		for name, desc := range e.Tools {
			gd, ok := got[name]
			switch {
			case !ok:
				out = append(out, Drift{Package: e.Slug, Kind: "tool_missing", Object: "tool " + name, Detail: "no longer served"})
			case gd != desc:
				out = append(out, Drift{Package: e.Slug, Kind: "tool_description", Object: "tool " + name, Detail: "the description differs from the manifest"})
			}
		}
		for name := range got {
			if _, ok := e.Tools[name]; !ok {
				out = append(out, Drift{Package: e.Slug, Kind: "tool_added", Object: "tool " + name, Detail: "served but not in the manifest"})
			}
		}
	}
	srvs, err := a.list(ctx, "/v1/servers?include_inactive=true")
	if err != nil {
		return nil, err
	}
	for _, s := range srvs {
		e, ok := servers[s.ID]
		if !ok {
			remove("unknown_server", "/v1/servers/"+pathEscape(s.ID), "virtual server "+s.Name, "a virtual server the Connector did not create")
			continue
		}
		if s.TeamID != e.TeamID || s.Visibility != "team" {
			out = append(out, Drift{Package: e.Slug, Kind: "server_team", Object: "virtual server " + e.Slug, Detail: fmt.Sprintf("team %q visibility %q", s.TeamID, s.Visibility)})
		}
		got, want := slices.Clone(s.AssociatedTools), slices.Clone(e.ToolIDs)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			out = append(out, Drift{Package: e.Slug, Kind: "server_tools", Object: "virtual server " + e.Slug, Detail: fmt.Sprintf("holds %d tools, registered %d", len(got), len(want))})
		}
	}
	for _, kind := range []struct{ path, name string }{{"/v1/prompts", "prompt"}, {"/v1/resources", "resource"}, {"/v1/a2a", "a2a_agent"}} {
		objs, err := a.list(ctx, kind.path+"?include_inactive=true")
		if err != nil {
			var api *APIError
			if asAPI(err, &api) && (api.Status == http.StatusNotFound || api.Status == http.StatusForbidden) {
				continue // the feature is off: nothing can exist
			}
			return nil, err
		}
		for _, o := range objs {
			remove("unknown_"+kind.name, kind.path+"/"+pathEscape(o.ID), kind.name+" "+o.Name, "the Connector creates no "+strings.ReplaceAll(kind.name, "_", " "))
		}
	}
	us, err := a.list(ctx, "/v1/auth/email/admin/users")
	if err != nil {
		return nil, err
	}
	for _, u := range us {
		if !users[u.Email] && u.IsActive {
			d := Drift{Kind: "unknown_user", Object: "user " + u.Email, Detail: "a user the Connector did not create", Removed: true}
			if err := a.RemoveUser(ctx, u.Email); err != nil {
				d.Removed, d.Detail = false, d.Detail+"; removal failed: "+err.Error()
			}
			out = append(out, d)
		}
	}
	ts, err := a.list(ctx, "/v1/teams?include_personal=false")
	if err != nil {
		return nil, err
	}
	for _, tm := range ts {
		if !teams[tm.ID] && !tm.IsPersonal {
			remove("unknown_team", "/v1/teams/"+pathEscape(tm.ID), "team "+tm.Name, "a team the Connector did not create")
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Package+out[i].Kind < out[j].Package+out[j].Kind })
	return out, nil
}

func asAPI(err error, target **APIError) bool {
	e, ok := err.(*APIError) //nolint:errorlint // Call returns *APIError unwrapped
	if ok {
		*target = e
	}
	return ok
}
