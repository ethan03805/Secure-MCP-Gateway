package library

import (
	"fmt"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// ReasonContainment refuses an enable whose containment could not be set
// up (FR-21.13), or a start whose revision has none.
const ReasonContainment = "CONTAINMENT_FAILED"

// Containment places each enabled revision in its own containment when it
// is enabled and removes it when the revision leaves the enabled and
// suspended states: the AppContainer profile, access entries, WFP filters
// and loopback exemption of the Windows machine mode (FR-21.13, FR-21.14,
// SR-4.6-2). winsandbox.Placements implements it.
type Containment interface {
	Ensure(winsandbox.PlacementRequest) (winsandbox.Placement, error)
	Remove(serverID, revision string) error
	Lookup(serverID, revision string) (winsandbox.Placement, bool)
}

// SlotBinding is how the configuration uses a package: its [[server]]
// alias and slot paths.
type SlotBinding struct {
	Alias string
	Slots map[string]string
}

// placementRequest builds the request for a revision: its unpacked tree,
// the scratch directory of the configured alias, and the manifest's slots
// that the configuration binds to a path (SR-4.6-2).
func (l *Library) placementRequest(r *Revision) (winsandbox.PlacementRequest, error) {
	if err := l.ensureTree(*r); err != nil {
		return winsandbox.PlacementRequest{}, err
	}
	m, _, err := l.Manifest(r.ServerID, r.Revision)
	if err != nil {
		return winsandbox.PlacementRequest{}, err
	}
	alias := r.Alias
	var slots map[string]string
	if l.bindings != nil {
		if b, ok := l.bindings(r.ServerID); ok {
			if b.Alias != "" {
				alias = b.Alias
			}
			slots = b.Slots
		}
	}
	req := winsandbox.PlacementRequest{ServerID: r.ServerID, Revision: r.Revision, Scratch: l.path("work", alias)}
	if r.ArtifactType != "oci" {
		req.Tree = l.TreePath(r.ArtifactSHA256)
	}
	for _, s := range m.Capabilities.Filesystem {
		if p, ok := slots[s.Slot]; ok {
			req.Roots = append(req.Roots, winsandbox.PathGrant{Path: p, Write: s.Mode == "rw"})
		}
	}
	return req, nil
}

// contain sets up the containment of a revision being enabled; the caller
// holds mu.
func (l *Library) contain(r *Revision, actor string) error {
	if l.containment == nil {
		return nil
	}
	req, err := l.placementRequest(r)
	if err == nil {
		var pl winsandbox.Placement
		if pl, err = l.containment.Ensure(req); err == nil {
			return l.evidence(audit.Event{Outcome: "containment_ready", ServerRevision: r.Key(),
				Detail: map[string]any{"actor": actor, "profile": pl.Profile, "sid": pl.SID, "broker_port": pl.BrokerPort}})
		}
	}
	return errf(ReasonContainment, "%s: containment not set up: %v", r.Key(), err)
}

// release removes the containment of a revision leaving the enabled and
// suspended states; the caller holds mu.
func (l *Library) release(r *Revision, actor string) error {
	if l.containment == nil {
		return nil
	}
	if _, ok := l.containment.Lookup(r.ServerID, r.Revision); !ok {
		return nil
	}
	if err := l.containment.Remove(r.ServerID, r.Revision); err != nil {
		_ = l.evidence(audit.Event{Outcome: "containment_remove_failed", ServerRevision: r.Key(), Detail: map[string]any{"actor": actor, "error": err.Error()}})
		return fmt.Errorf("%s: containment not removed: %w", r.Key(), err)
	}
	return l.evidence(audit.Event{Outcome: "containment_removed", ServerRevision: r.Key(), Detail: map[string]any{"actor": actor}})
}

// placement returns the containment of an enabled revision for a start:
// nil without containment, an error when the revision has none.
func (l *Library) placement(r Revision) (*winsandbox.Placement, error) {
	if l.containment == nil {
		return nil, nil
	}
	pl, ok := l.containment.Lookup(r.ServerID, r.Revision)
	if !ok {
		return nil, errf(ReasonContainment, "%s has no AppContainer placement; run the enable step again as an administrator (smcpctl package enable)", r.Key())
	}
	return &pl, nil
}

func placementProfile(pl *winsandbox.Placement) string {
	if pl == nil {
		return ""
	}
	return pl.Profile
}

func placementPort(pl *winsandbox.Placement) uint16 {
	if pl == nil {
		return 0
	}
	return pl.BrokerPort
}
