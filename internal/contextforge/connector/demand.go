package connector

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// IdleStop is how long the bundled instance keeps running after the last
// enabled hosted revision is disabled and no probe runs (FR-22.23).
const IdleStop = 30 * time.Second

// demandTick is how often the Connector compares the demand with the
// instance's state.
var demandTick = 5 * time.Second

// hostedEnabled reports whether an enabled hosted package revision exists.
func (c *Connector) hostedEnabled() bool {
	for _, r := range c.o.Library.Revisions() {
		if r.ArtifactType == packaging.ArtifactHosted && r.State == library.StateEnabled {
			return true
		}
	}
	return false
}

func (c *Connector) holdProbe() {
	c.demandMu.Lock()
	c.probes++
	c.demandMu.Unlock()
}

func (c *Connector) releaseProbe() {
	c.demandMu.Lock()
	c.probes--
	c.demandMu.Unlock()
}

// demanded reports whether the instance should run: an enabled hosted
// revision, a running probe, or an Operator's start (FR-22.23, FR-22.41).
func (c *Connector) demanded() bool {
	c.demandMu.Lock()
	held := c.probes > 0 || c.operatorHold
	c.demandMu.Unlock()
	return held || c.hostedEnabled()
}

// onDemand starts the instance while it is demanded and stops it IdleStop
// after the demand ends.
func (c *Connector) onDemand(ctx context.Context) {
	if c.inst == nil {
		return
	}
	st := c.inst.Status().State
	if c.demanded() {
		c.idleSince = time.Time{}
		if st == bundle.StateStopped && c.hostedEnabled() {
			if err := c.StartInstance(ctx, "E-36"); err != nil {
				c.o.Log.Warn("starting the bundled ContextForge instance for enabled hosted packages", "error", err)
			}
		}
		return
	}
	if st == bundle.StateStopped {
		c.idleSince = time.Time{}
		return
	}
	now := c.o.Now()
	if c.idleSince.IsZero() {
		c.idleSince = now
	}
	if now.Sub(c.idleSince) >= IdleStop-demandTick {
		if err := c.StopInstance(ctx, "E-36"); err != nil {
			c.o.Log.Warn("stopping the idle bundled ContextForge instance", "error", err)
		}
		c.idleSince = time.Time{}
	}
}

// UninstallReport says what Uninstall removed.
type UninstallReport struct {
	CredentialsRetired int      `json:"credentials_retired"`
	Suspended          []string `json:"suspended_revisions"`
	VolumeRemoved      bool     `json:"volume_removed"`
	ImageRemoved       bool     `json:"image_removed"`
}

// Uninstall removes the bundled instance (FR-22.32): it stops it, removes
// its data volume (D-16) and image, retires its credentials in the vault,
// suspends every enabled hosted package revision and forgets the image
// verification. The journal and the hosted packages' Library records stay.
func (c *Connector) Uninstall(ctx context.Context, actor string) (UninstallReport, error) {
	var rep UninstallReport
	if c.inst == nil {
		if c.instErr != nil {
			return rep, c.instErr
		}
		return rep, packaging.Errf(contextforge.ReasonContextForgeDisabled, "the bundled instance is not configured")
	}
	c.demandMu.Lock()
	c.operatorHold = false
	c.demandMu.Unlock()
	if err := c.StopInstance(ctx, actor); err != nil {
		return rep, err
	}
	for _, r := range c.o.Library.Revisions() {
		if r.ArtifactType == packaging.ArtifactHosted && r.State == library.StateEnabled {
			if _, _, err := c.o.Library.SetState(r.ServerID, r.Revision, library.StateSuspended, "the bundled ContextForge instance was uninstalled", actor); err != nil {
				return rep, err
			}
			rep.Suspended = append(rep.Suspended, r.Key())
		}
	}
	rep.VolumeRemoved = c.inst.RemoveVolume(ctx) == nil
	rep.ImageRemoved = c.inst.RemoveImage(ctx) == nil
	n, err := c.o.Broker.RetireComponent(component, actor)
	rep.CredentialsRetired = n
	if err != nil {
		return rep, err
	}
	_ = os.Remove(filepath.Join(c.dir, "verified.json"))
	if c.o.Recorder != nil {
		if err := c.o.Recorder.Commit(c.instanceEvent("uninstalled", "", map[string]any{"actor": actor, "credentials_retired": n,
			"suspended": rep.Suspended, "volume_removed": rep.VolumeRemoved, "image_removed": rep.ImageRemoved})); err != nil {
			return rep, err
		}
	}
	return rep, nil
}
