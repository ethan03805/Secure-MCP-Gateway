package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Upgrade with rollback of the bundled instance (SRS FR-22.31).
//
// Two locks are kept under <state>/contextforge:
//
//   - the active lock, the release the instance is to run: lock.json
//     (with lock.json.minisig) when a signed release lock was installed by
//     an upgrade, otherwise the release lock compiled into the Gateway;
//   - the running lock (running.lock.json), the release the instance last
//     ran and D-16 belongs to.
//
// The version changes only through an upgrade: an explicit one
// (`smcpctl contextforge upgrade`, to a signed lock or to the compiled lock
// of a newly installed Gateway release), or the start after a newly
// installed Gateway release changed the active lock. Either backs up D-16
// and restores it, with the previous release, when a step fails.

// Reason codes of an upgrade.
const (
	// ReasonUpgradeRefused: the lock given to an upgrade is unsigned, its
	// signature does not verify with the release key, it is malformed, or
	// it pins the release the instance already runs.
	ReasonUpgradeRefused = "CONTEXTFORGE_UPGRADE_REFUSED"
	// ReasonUpgradeRolledBack: a step of the upgrade failed and the
	// previous release and D-16 were restored.
	ReasonUpgradeRolledBack = "CONTEXTFORGE_UPGRADE_ROLLED_BACK"
)

// Files of the locks under <state>/contextforge.
const (
	activeLockFile  = "lock.json"
	activeSigFile   = "lock.json.minisig"
	runningLockFile = "running.lock.json"
)

// Upgradable is a Runner whose release can be switched: the container
// (bundle.Instance) and the managed process (bundle.Process).
type Upgradable interface {
	BackupData(ctx context.Context) error
	RestoreData(ctx context.Context) error
	DropBackup(ctx context.Context) error
	RemoveImageRef(ctx context.Context, ref string) error
}

var (
	_ Upgradable = (*bundle.Instance)(nil)
	_ Upgradable = (*bundle.Process)(nil)
)

// lock is the release the bundled instance is to run (the active lock).
func (c *Connector) lock() *contextforge.LockedRelease {
	if l := c.active.Load(); l != nil {
		return l
	}
	l := contextforge.ReleaseLock().ContextForge
	return &l
}

func readLock(path string) (*contextforge.LockedRelease, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l, err := contextforge.ParseLock(raw)
	if err != nil {
		return nil, err
	}
	return &l.ContextForge, nil
}

// loadActiveLock reads the lock an earlier upgrade installed; without one
// the instance runs the compiled release lock.
func (c *Connector) loadActiveLock() {
	l, err := readLock(filepath.Join(c.dir, activeLockFile))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		c.o.Log.Warn("the installed ContextForge lock is unreadable; using the release lock of this Gateway", "error", err)
		return
	}
	c.active.Store(l)
}

// runningLock is the release the instance last ran (nil before its first
// start).
func (c *Connector) runningLock() *contextforge.LockedRelease {
	l, err := readLock(filepath.Join(c.dir, runningLockFile))
	if err != nil {
		return nil
	}
	return l
}

func (c *Connector) saveRunningLock(r *contextforge.LockedRelease) error {
	raw, err := json.MarshalIndent(contextforge.Lock{LockVersion: 1, ContextForge: *r}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.dir, runningLockFile), append(raw, '\n'), 0o600)
}

func sameRelease(a, b *contextforge.LockedRelease) bool {
	if a.Version != b.Version || a.Image.IndexDigest != b.Image.IndexDigest {
		return false
	}
	for _, p := range contextforge.WheelPlatforms {
		if a.WheelSetDigest(p) != b.WheelSetDigest(p) {
			return false
		}
	}
	return true
}

// pendingUpgrade is the release change a start must perform: the instance
// last ran another release than the active lock (a newly installed Gateway
// release).
func (c *Connector) pendingUpgrade() (from, to *contextforge.LockedRelease) {
	run := c.runningLock()
	if run == nil || sameRelease(run, c.lock()) {
		return nil, nil
	}
	return run, c.lock()
}

// artifact is the image reference, or the managed process's interpreter,
// of release r.
func (c *Connector) artifact(r *contextforge.LockedRelease) string {
	if c.process != nil {
		return bundle.VenvPython(filepath.Join(c.dir, "instance"), r.Version)
	}
	return r.ImageRef(c.platform)
}

func (c *Connector) setArtifact(r *contextforge.LockedRelease) error {
	switch inst := c.inst.(type) {
	case *bundle.Instance:
		return inst.SetImage(r.ImageRef(c.platform))
	case *bundle.Process:
		return inst.SetPython(c.artifact(r))
	case interface {
		SetRelease(*contextforge.LockedRelease) error
	}:
		return inst.SetRelease(r)
	}
	return nil
}

// lockKeys are the keys a release lock given to an upgrade must be signed
// with: the release key (SECURITY.md) unless the Options name others.
func (c *Connector) lockKeys() ([]minisign.PublicKey, error) {
	if len(c.o.LockKeys) > 0 {
		return c.o.LockKeys, nil
	}
	var pk minisign.PublicKey
	if err := pk.UnmarshalText([]byte(contextforge.ReleaseKey)); err != nil {
		return nil, err
	}
	return []minisign.PublicKey{pk}, nil
}

// UpgradeReport says what an upgrade did.
type UpgradeReport struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Source     string   `json:"source"` // "release" or "signed_lock"
	Outcome    string   `json:"outcome"`
	Step       string   `json:"failed_step,omitempty"`
	Error      string   `json:"error,omitempty"`
	Packages   []string `json:"hosted_packages_checked"`
	HealthSecs float64  `json:"seconds_to_health,omitempty"`
}

func newerTag(a, b string) bool {
	pa, pb := tagParts(a), tagParts(b)
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func tagParts(v string) [3]int {
	var p [3]int
	_, _ = fmt.Sscanf(strings.TrimPrefix(v, "v"), "%d.%d.%d", &p[0], &p[1], &p[2])
	return p
}

// Upgrade changes the bundled instance's release (FR-22.31): to the lock
// raw when it is given with its minisign signature sig, which must verify
// with the release key, and otherwise to the release lock compiled into
// this Gateway when that is newer than the release the instance runs.
func (c *Connector) Upgrade(ctx context.Context, actor string, raw, sig []byte) (UpgradeReport, error) {
	from := c.runningLock()
	if from == nil {
		from = c.lock()
	}
	rep := UpgradeReport{From: from.Version, Source: "release", Packages: []string{}}
	if !c.o.Config.ContextForge.Bundled {
		return rep, packaging.Errf(contextforge.ReasonContextForgeDisabled, "[contextforge] bundled is false")
	}
	if c.instErr != nil {
		return rep, c.instErr
	}
	compiled := contextforge.ReleaseLock()
	to := &compiled.ContextForge
	if raw != nil {
		rep.Source = "signed_lock"
		if len(sig) == 0 {
			return c.refuseUpgrade(rep, actor, "the release lock is not signed: give its minisign signature")
		}
		keys, err := c.lockKeys()
		if err != nil {
			return c.refuseUpgrade(rep, actor, "release key: %v", err)
		}
		verified := false
		for _, k := range keys {
			if minisign.Verify(k, raw, sig) {
				verified = true
			}
		}
		if !verified {
			return c.refuseUpgrade(rep, actor, "the signature of the release lock does not verify with the release key")
		}
		l, err := contextforge.ParseLock(raw)
		if err != nil {
			return c.refuseUpgrade(rep, actor, "%v", err)
		}
		to = &l.ContextForge
	} else if !newerTag(to.Version, from.Version) && sameRelease(c.lock(), from) {
		rep.To = to.Version
		return c.refuseUpgrade(rep, actor, "this Gateway release pins ContextForge %s, which is not newer than the running %s; give a signed release lock to change it", to.Version, from.Version)
	}
	rep.To = to.Version
	if sameRelease(to, from) {
		return c.refuseUpgrade(rep, actor, "the bundled instance already runs ContextForge %s", to.Version)
	}
	c.instMu.Lock()
	defer c.instMu.Unlock()
	return c.upgradeLocked(ctx, actor, rep, from, to, raw, sig)
}

func (c *Connector) refuseUpgrade(rep UpgradeReport, actor, format string, args ...any) (UpgradeReport, error) {
	err := packaging.Errf(ReasonUpgradeRefused, format, args...)
	rep.Outcome, rep.Error = "refused", err.Error()
	if c.o.Recorder != nil {
		if eerr := c.o.Recorder.Commit(c.instanceEvent("upgrade_refused", ReasonUpgradeRefused, map[string]any{"actor": actor, "error": err.Error(),
			"from": rep.From, "to": rep.To, "source": rep.Source})); eerr != nil {
			return rep, eerr
		}
	}
	return rep, err
}

// upgradeLocked performs the upgrade from release cur to release to; the
// caller holds instMu. It stops the instance, backs up D-16, verifies the
// new release's artifacts (FR-22.19, FR-22.20), generates new instance
// credentials (FR-22.28), starts the new release, waits for its health
// within the CP-47 wait, reconciles it (FR-22.33) and registers every
// enabled hosted package again, reading its tool list against the
// manifest (FR-22.29, FR-22.34). When any step fails it restores the
// previous release, its credentials, its verification and D-16, and starts
// it again when it was running.
func (c *Connector) upgradeLocked(ctx context.Context, actor string, rep UpgradeReport, cur, to *contextforge.LockedRelease, raw, sig []byte) (UpgradeReport, error) {
	up, ok := c.inst.(Upgradable)
	if !ok {
		return c.refuseUpgrade(rep, actor, "this bundled instance cannot be upgraded")
	}
	if c.o.Recorder != nil {
		if err := c.o.Recorder.Commit(c.instanceEvent("upgrade_started", "", map[string]any{"actor": actor, "from": cur.Version, "to": to.Version, "source": rep.Source})); err != nil {
			return rep, err
		}
	}
	prevActive := c.active.Load()
	wasRunning := c.inst.Status().State != bundle.StateStopped
	oldVer, _ := bundle.LoadVerification(c.dir)
	if err := c.inst.Stop(ctx); err != nil {
		return rep, err
	}
	c.resetHosted()
	// The instance's artifact is the running release's while D-16 is
	// copied and while it is restored.
	if err := c.setArtifact(cur); err != nil {
		return c.restartAfter(ctx, rep, actor, wasRunning, cur, prevActive, "switch", err)
	}
	if err := up.BackupData(ctx); err != nil {
		return c.restartAfter(ctx, rep, actor, wasRunning, cur, prevActive, "backup", err)
	}
	oldCreds, err := c.credentials()
	if err != nil {
		return c.restartAfter(ctx, rep, actor, wasRunning, cur, prevActive, "credentials", err)
	}
	rollback := func(step string, cause error) (UpgradeReport, error) {
		c.o.Log.Warn("ContextForge upgrade failed; restoring the previous release", "step", step, "error", cause)
		bg := context.WithoutCancel(ctx)
		_ = c.inst.Stop(bg)
		c.resetHosted()
		c.storeActive(prevActive)
		var errs []error
		if err := c.setArtifact(cur); err != nil {
			errs = append(errs, err)
		}
		if err := up.RestoreData(bg); err != nil {
			errs = append(errs, fmt.Errorf("restore D-16: %w", err))
		}
		for k, v := range oldCreds {
			val := v
			if err := c.o.Broker.RotateComponent(component, credentialName(k), func() ([]byte, error) { return []byte(val), nil }); err != nil {
				errs = append(errs, fmt.Errorf("restore credential %s: %w", credentialName(k), err))
			}
		}
		if oldVer != nil {
			if err := oldVer.Save(c.dir); err != nil {
				errs = append(errs, err)
			}
		} else {
			_ = os.Remove(filepath.Join(c.dir, "verified.json"))
		}
		c.verified.Store(oldVer)
		rep.Outcome, rep.Step, rep.Error = "rolled_back", step, cause.Error()
		d := map[string]any{"actor": actor, "from": cur.Version, "to": to.Version, "source": rep.Source, "failed_step": step, "error": cause.Error()}
		if len(errs) > 0 {
			d["restore_errors"] = errors.Join(errs...).Error()
		}
		if wasRunning && len(errs) == 0 {
			if err := c.startLocked(bg, actor, cur); err != nil {
				d["restart_error"] = err.Error()
			}
		}
		if c.o.Recorder != nil {
			_ = c.o.Recorder.Commit(c.instanceEvent("upgrade_rolled_back", ReasonUpgradeRolledBack, d))
		}
		if len(errs) > 0 {
			return rep, packaging.Wrap(ReasonUpgradeRolledBack, "the upgrade failed at "+step+" and restoring the previous release failed", errors.Join(append([]error{cause}, errs...)...))
		}
		return rep, packaging.Wrap(ReasonUpgradeRolledBack, "the upgrade to ContextForge "+to.Version+" failed at "+step+"; ContextForge "+cur.Version+" and its data were restored", cause)
	}

	vctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	newVer, err := c.verifier.Verify(vctx, to, c.platform, c.o.Now())
	cancel()
	if err != nil {
		return rollback("verify", err)
	}
	if err := c.setArtifact(to); err != nil {
		return rollback("switch", err)
	}
	// FR-22.28: new instance credentials at each upgrade.
	for _, k := range bundle.CredentialKeys {
		if err := c.o.Broker.RotateComponent(component, credentialName(k), func() ([]byte, error) {
			v, err := bundle.NewCredential()
			return []byte(v), err
		}); err != nil {
			return rollback("credentials", err)
		}
	}
	if err := newVer.Save(c.dir); err != nil {
		return rollback("verify", err)
	}
	c.verified.Store(newVer)
	c.active.Store(to)
	started := time.Now()
	if err := c.prepareEgress(ctx); err != nil {
		return rollback("start", err)
	}
	if err := c.inst.Start(ctx); err != nil {
		return rollback("start", err)
	}
	wait := c.o.UpgradeHealthWait
	if wait <= 0 {
		wait = bundle.DefaultHealthWait
	}
	deadline := time.Now().Add(wait)
	for !c.inst.Healthy() {
		if time.Now().After(deadline) || ctx.Err() != nil {
			return rollback("health", fmt.Errorf("no healthy answer within %s", wait))
		}
		time.Sleep(250 * time.Millisecond)
	}
	rep.HealthSecs = time.Since(started).Round(100 * time.Millisecond).Seconds()
	checked, err := c.reregisterHosted(ctx)
	rep.Packages = checked
	if err != nil {
		return rollback("hosted_packages", err)
	}
	switch {
	case raw != nil:
		if err := os.WriteFile(filepath.Join(c.dir, activeLockFile), raw, 0o600); err != nil {
			return rollback("install_lock", err)
		}
		if err := os.WriteFile(filepath.Join(c.dir, activeSigFile), sig, 0o600); err != nil {
			return rollback("install_lock", err)
		}
	case sameRelease(to, &contextforge.ReleaseLock().ContextForge):
		// The compiled lock is the active one again.
		_ = os.Remove(filepath.Join(c.dir, activeLockFile))
		_ = os.Remove(filepath.Join(c.dir, activeSigFile))
	}
	if err := c.saveRunningLock(to); err != nil {
		return rollback("install_lock", err)
	}
	_ = up.DropBackup(context.WithoutCancel(ctx))
	if old := c.artifact(cur); old != c.artifact(to) {
		_ = up.RemoveImageRef(context.WithoutCancel(ctx), old)
	}
	rep.Outcome = "upgraded"
	if c.o.Recorder != nil {
		if err := c.o.Recorder.Commit(c.instanceEvent("upgraded", "", map[string]any{"actor": actor, "from": cur.Version, "to": to.Version, "source": rep.Source,
			"platform_digest": newVer.PlatformDigest, "hosted_packages": checked, "seconds_to_health": rep.HealthSecs})); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func (c *Connector) storeActive(l *contextforge.LockedRelease) {
	c.active.Store(l)
}

// restartAfter handles a failure before anything changed: the previous
// release starts again when it was running.
func (c *Connector) restartAfter(ctx context.Context, rep UpgradeReport, actor string, wasRunning bool, cur, prevActive *contextforge.LockedRelease, step string, cause error) (UpgradeReport, error) {
	rep.Outcome, rep.Step, rep.Error = "rolled_back", step, cause.Error()
	c.storeActive(prevActive)
	if wasRunning {
		_ = c.startLocked(context.WithoutCancel(ctx), actor, cur)
	}
	if c.o.Recorder != nil {
		_ = c.o.Recorder.Commit(c.instanceEvent("upgrade_rolled_back", ReasonUpgradeRolledBack, map[string]any{"actor": actor, "failed_step": step, "error": cause.Error()}))
	}
	return rep, packaging.Wrap(ReasonUpgradeRolledBack, "the upgrade failed at "+step, cause)
}

// startLocked starts the instance of release r with its recorded
// verification; the caller holds instMu.
func (c *Connector) startLocked(ctx context.Context, actor string, r *contextforge.LockedRelease) error {
	ver, err := bundle.LoadVerification(c.dir)
	if err != nil || !ver.Matches(r, c.platform) {
		return fmt.Errorf("no verification of ContextForge %s to start it again", r.Version)
	}
	if err := c.verifier.LocalDigestOK(ctx, ver, r.Image.Reference); err != nil {
		return err
	}
	c.verified.Store(ver)
	if err := c.prepareEgress(ctx); err != nil {
		return err
	}
	if err := c.inst.Start(ctx); err != nil {
		return err
	}
	if c.o.Recorder != nil {
		return c.o.Recorder.Commit(c.instanceEvent("started", "", map[string]any{"actor": actor, "unconfined": !c.o.Enforced}))
	}
	return nil
}

// resetHosted forgets the registrations of a stopped instance.
func (c *Connector) resetHosted() {
	c.hostedMu.Lock()
	for _, hp := range c.hosted {
		c.dropEndpoint(hp.key())
	}
	c.hosted = map[string]*hostedPkg{}
	c.hostedMu.Unlock()
}

// reregisterHosted registers every enabled hosted package in the upgraded
// instance as a launch does (ResolveHosted: the reconciliation of the new
// start, team, user, gateway, virtual server, token, the served tool list
// against the manifest, the scope self-check) and returns the revisions it
// checked.
func (c *Connector) reregisterHosted(ctx context.Context) ([]string, error) {
	lib, ok := c.o.Library.(interface {
		Manifest(id, rev string) (*packaging.Manifest, []byte, error)
	})
	if !ok {
		return nil, errors.New("the library cannot read manifests")
	}
	checked := []string{}
	for _, r := range c.o.Library.Revisions() {
		if r.ArtifactType != packaging.ArtifactHosted || r.State != library.StateEnabled {
			continue
		}
		m, _, err := lib.Manifest(r.ServerID, r.Revision)
		if err != nil {
			return checked, fmt.Errorf("%s: %w", r.Key(), err)
		}
		if _, err := c.ResolveHosted(config.Server{Alias: r.Alias, Package: r.ServerID}, m, r); err != nil {
			return checked, fmt.Errorf("%s: %w", r.Key(), err)
		}
		checked = append(checked, r.Key())
	}
	if len(checked) == 0 {
		// Still reconcile the new start (FR-22.33): nothing of an earlier
		// run stays in D-16.
		if _, err := c.admin().Reconcile(ctx, nil); err != nil {
			return checked, err
		}
		c.hostedMu.Lock()
		c.cleanedAt = c.inst.Status().StartedAt
		c.hostedMu.Unlock()
	}
	return checked, nil
}
