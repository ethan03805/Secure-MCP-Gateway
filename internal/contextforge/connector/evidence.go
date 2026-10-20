package connector

import (
	"maps"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
)

// RouteVia is the route marker of a call to a hosted package (FR-22.39).
const RouteVia = "contextforge"

// setRoute records the route fields of an enabled hosted revision: the
// package server ID and revision, its ContextForge virtual server and the
// bundled instance's version and digest (FR-22.39).
func (c *Connector) setRoute(serverID, revision, virtualServer string) {
	lock := contextforge.ReleaseLock().ContextForge
	r := map[string]string{"via": RouteVia, "server_id": serverID, "revision": revision, "virtual_server": virtualServer,
		"instance_version": lock.Version, "instance_digest": c.instanceDigest()}
	c.routeMu.Lock()
	c.routes[serverID+"@"+revision] = r
	c.routeMu.Unlock()
}

// Decorate is an audit.Fanout decorator: the events of a call to a hosted
// package (its server revision is a registered hosted revision) carry the
// route fields; every other event is left alone, so a local package's
// events have no via marker (FR-22.39).
func (c *Connector) Decorate(ev *audit.Event) {
	if ev.ServerRevision == "" || ev.Route != nil {
		return
	}
	c.routeMu.RLock()
	r, ok := c.routes[ev.ServerRevision]
	c.routeMu.RUnlock()
	if ok {
		ev.Route = maps.Clone(r)
		if serverClaim(ev) {
			ev.Route[RouteEvidence] = EvidenceServerAsserted
		}
	}
}

// RouteEvidence is the route field that labels an event of a hosted call
// whose content the bundled instance asserted, with the value
// EvidenceServerAsserted (SR-6.18-2).
const (
	RouteEvidence          = "evidence"
	EvidenceServerAsserted = "server_asserted"
)

// serverClaim reports whether an event records something received from
// the bundled instance rather than the Gateway's own action: the text it
// asserted (an error message, a notification), a call's completion, which
// records the result it returned, and a failure the dispatcher reports
// for its answer (SR-6.18-2).
func serverClaim(ev *audit.Event) bool {
	switch {
	case ev.Class == "server_asserted":
		return true
	case ev.Phase == audit.PhaseCompleted:
		return true
	case ev.Origin == "E-10" && (ev.Phase == audit.PhaseFailed || ev.Phase == audit.PhaseIndeterminate):
		return true
	}
	return false
}

// instanceDigest is the digest of the bundled instance's verified
// artifacts: the platform image digest, or the wheel-set digest of the
// managed-process form (FR-22.11, FR-22.39).
func (c *Connector) instanceDigest() string {
	if v := c.verified.Load(); v != nil {
		return v.PlatformDigest
	}
	return contextforge.ReleaseLock().ContextForge.Image.Platforms[c.platform]
}
