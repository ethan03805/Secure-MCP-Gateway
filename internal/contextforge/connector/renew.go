package connector

import (
	"context"
	"net/http"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// DefaultRenewBefore is how long before its expiry a package token is
// renewed (FR-22.29): tokens are minted for one day.
const DefaultRenewBefore = time.Hour

// renewTokens renews every registered package token that expires within
// RenewBefore (FR-22.29): it mints a new token owned by the package's user
// for its team and virtual server, runs the scope self-check with the new
// tokens before any is used, then switches the package's connection to the
// new token (it is read for each request, FR-22.36) and revokes the old
// one. A self-check finding stops the bundled instance and suspends every
// hosted package with CONTEXTFORGE_SCOPE_BROKEN.
func (c *Connector) renewTokens(ctx context.Context) {
	if c.inst == nil || !c.inst.Healthy() {
		return
	}
	c.hostedMu.Lock()
	defer c.hostedMu.Unlock()
	now := c.o.Now()
	type renewal struct {
		hp   *hostedPkg
		next bundle.Provisioned
	}
	var due []renewal
	a := c.admin()
	for _, hp := range c.hosted {
		if hp.Prov.Expires.IsZero() || hp.Prov.Expires.Sub(now) > c.o.RenewBefore {
			continue
		}
		user := "user-" + hp.Prov.Slug
		vals, err := c.o.Broker.DeliverComponent(component, []string{user})
		if err != nil {
			c.renewEvent("token_renewal_failed", hp, map[string]any{"error": err.Error()})
			continue
		}
		pw := string(vals[user])
		clear(vals[user])
		next := *hp.Prov
		next.ToolIDs, next.Tools = append([]string(nil), hp.Prov.ToolIDs...), append([]string(nil), hp.Prov.Tools...)
		if err := a.RenewToken(ctx, &next, pw); err != nil {
			c.renewEvent("token_renewal_failed", hp, map[string]any{"error": err.Error()})
			continue
		}
		due = append(due, renewal{hp, next})
	}
	if len(due) == 0 {
		return
	}
	// The self-check runs with the new tokens of the renewed packages and
	// the current tokens of the others.
	byID := map[string]*bundle.Provisioned{}
	for id, hp := range c.hosted {
		p := *hp.Prov
		byID[id] = &p
	}
	for _, r := range due {
		n := r.next
		byID[r.hp.Prov.ServerID] = &n
	}
	pkgs := make([]*bundle.Provisioned, 0, len(byID))
	for _, p := range byID {
		pkgs = append(pkgs, p)
	}
	if f := a.SelfCheck(ctx, pkgs); len(f) > 0 {
		for _, r := range due {
			_ = a.Call(context.WithoutCancel(ctx), http.MethodDelete, "/v1/tokens/admin/"+r.next.TokenID, "", nil, nil)
		}
		c.scopeBroken(packaging.Errf(bundle.ReasonScopeBroken, "the scope self-check after token renewal found %d findings, for example %s: %s", len(f), f[0].Probe, f[0].Detail))
		return
	}
	for _, r := range due {
		old := r.hp.Prov.TokenID
		next := r.next
		r.hp.Prov = &next
		r.hp.Expected.Provisioned = next
		r.hp.setToken(next.Token)
		if old != "" && old != next.TokenID {
			_ = a.Call(ctx, http.MethodDelete, "/v1/tokens/admin/"+old, "", nil, nil)
		}
		c.renewEvent("token_renewed", r.hp, map[string]any{"expires": next.Expires.UTC().Format(time.RFC3339)})
	}
}

func (c *Connector) renewEvent(outcome string, hp *hostedPkg, d map[string]any) {
	if c.o.Recorder == nil {
		return
	}
	d["package"], d["server_revision"], d["virtual_server"] = hp.Prov.Slug, hp.key(), hp.Prov.ServerID
	ev := c.instanceEvent(outcome, "", d)
	ev.ServerRevision = hp.key()
	_ = c.o.Recorder.Record(ev)
}
