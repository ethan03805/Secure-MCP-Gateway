package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ReasonVaultRequired: [contextforge] bundled is true but the Secret Vault
// that holds the instance's credentials is not configured (FR-22.28).
const ReasonVaultRequired = "CONTEXTFORGE_VAULT_REQUIRED"

// ReasonEngineMissing: no container engine runs the bundled instance.
const ReasonEngineMissing = "CONTEXTFORGE_ENGINE_MISSING"

// component is the Secret Broker component ID of the instance credentials.
const component = "contextforge"

// ClassInstance is the event class of the bundled instance's lifecycle.
const ClassInstance = "contextforge"

// InstanceView is the bundled instance's state for G-15 and smcpctl
// (FR-22.41).
type InstanceView struct {
	State       string    `json:"state"` // disabled, unavailable, stopped, starting, healthy, unhealthy
	Detail      string    `json:"detail,omitempty"`
	Version     string    `json:"version"`
	Image       string    `json:"image"`
	Verified    string    `json:"verified,omitempty"` // time of the last verification of this image
	Restarts    int       `json:"restarts"`
	StartedAt   time.Time `json:"started_at,omitzero"`
	ReasonCode  string    `json:"reason_code,omitempty"`
	Unconfined  bool      `json:"unconfined"`
	EngineIsPod bool      `json:"podman"`
}

func credentialName(key string) string {
	return strings.ReplaceAll(strings.ToLower(key), "_", "-")
}

// setupInstance prepares the bundled instance when [contextforge] bundled
// is true; it starts nothing.
func (c *Connector) setupInstance() {
	cf := c.o.Config.ContextForge
	if c.o.Broker == nil {
		c.instErr = packaging.Errf(ReasonVaultRequired, "the bundled ContextForge instance keeps its credentials in the Secret Vault; run smcpctl secrets init and add a [secrets] table")
		return
	}
	eng := bundle.Engine{Path: cf.Engine}
	if eng.Path == "" {
		var err error
		if eng, err = bundle.FindEngine(); err != nil {
			c.instErr = packaging.Errf(ReasonEngineMissing, "%v", err)
			return
		}
	} else {
		eng.Podman = strings.HasSuffix(eng.Path, "podman")
	}
	cosign := cf.Cosign
	if cosign == "" {
		cosign, _ = exec.LookPath("cosign")
	}
	lock := contextforge.ReleaseLock().ContextForge
	c.platform = "linux/" + runtime.GOARCH
	sum := sha256.Sum256([]byte(c.o.Config.State.Dir))
	l := c.o.Config.Limits
	inst, err := bundle.New(bundle.Options{Engine: eng, Image: lock.ImageRef(c.platform), Name: "smcp-contextforge-" + hex.EncodeToString(sum[:4]),
		Settings:    bundle.Settings{Limits: bundle.Limits{UpstreamTimeout: l.UpstreamTimeout.Duration, CallsPerMinute: l.PrincipalCallsPerMin, Concurrency: l.ToolConcurrencyTotal}},
		Credentials: c.credentials, OnState: c.instanceState, Log: c.o.Log})
	if err != nil {
		c.instErr = err
		return
	}
	c.inst = inst
	c.verifier = &bundle.Verifier{Cosign: cosign, Engine: eng}
}

// credentials creates the instance credentials in the vault on first use
// and delivers them through the Secret Broker (FR-22.28).
func (c *Connector) credentials() (bundle.Credentials, error) {
	names := make([]string, 0, len(bundle.CredentialKeys))
	for _, k := range bundle.CredentialKeys {
		n := credentialName(k)
		names = append(names, n)
		if _, err := c.o.Broker.EnsureComponent(component, n, func() ([]byte, error) {
			v, err := bundle.NewCredential()
			return []byte(v), err
		}); err != nil {
			return nil, err
		}
	}
	vals, err := c.o.Broker.DeliverComponent(component, names)
	if err != nil {
		return nil, err
	}
	out := bundle.Credentials{}
	for _, k := range bundle.CredentialKeys {
		v := vals[credentialName(k)]
		out[k] = string(v)
		clear(v)
	}
	return out, nil
}

func (c *Connector) instanceState(state, detail string) {
	if c.o.Recorder == nil {
		return
	}
	d := map[string]any{"state": state}
	if detail != "" {
		d["detail"] = detail
	}
	_ = c.o.Recorder.Record(c.instanceEvent("instance_"+state, "", d))
}

func (c *Connector) instanceEvent(outcome, reason string, d map[string]any) audit.Event {
	l := contextforge.ReleaseLock().ContextForge
	d["version"], d["image"] = l.Version, l.ImageRef(c.platform)
	return audit.Event{Class: ClassInstance, Origin: "E-36", Outcome: outcome, ReasonCode: reason, PolicyStatus: "not_evaluated", Detail: d}
}

// StartInstance verifies the image when it was not verified before (or
// changed), checks the local image digest, and starts the instance. A
// refusal is recorded with its reason.
func (c *Connector) StartInstance(ctx context.Context, actor string) error {
	if !c.o.Config.ContextForge.Bundled {
		return packaging.Errf(contextforge.ReasonContextForgeDisabled, "[contextforge] bundled is false")
	}
	refuse := func(err error) error {
		if c.o.Recorder != nil {
			if eerr := c.o.Recorder.Commit(c.instanceEvent("start_refused", packaging.ReasonOf(err), map[string]any{"actor": actor, "error": err.Error()})); eerr != nil {
				return eerr
			}
		}
		return err
	}
	if c.instErr != nil {
		return refuse(c.instErr)
	}
	lock := contextforge.ReleaseLock().ContextForge
	c.instMu.Lock()
	defer c.instMu.Unlock()
	ver, err := bundle.LoadVerification(c.dir)
	if err != nil {
		return refuse(err)
	}
	if !ver.Matches(&lock, c.platform) {
		vctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		ver, err = c.verifier.Verify(vctx, &lock, c.platform, c.o.Now())
		cancel()
		if err != nil {
			return refuse(err)
		}
		if err := ver.Save(c.dir); err != nil {
			return refuse(err)
		}
		// SR-3.2-2: the verified source-to-image binding, once per image.
		if c.o.Recorder != nil {
			if err := c.o.Recorder.Commit(c.instanceEvent("image_verified", "", map[string]any{"source_tag": ver.SourceTag, "source_commit": ver.SourceCommit,
				"workflow": ver.Workflow, "issuer": ver.Issuer, "index_digest": ver.IndexDigest, "platform": ver.Platform,
				"platform_digest": ver.PlatformDigest, "sbom": ver.SBOM, "actor": actor})); err != nil {
				return err
			}
		}
	} else if err := c.verifier.LocalDigestOK(ctx, ver, lock.Image.Reference); err != nil {
		return refuse(err)
	}
	c.verified = ver
	if err := c.inst.Start(ctx); err != nil {
		return refuse(err)
	}
	if c.o.Recorder != nil {
		return c.o.Recorder.Commit(c.instanceEvent("started", "", map[string]any{"actor": actor, "unconfined": !c.o.Enforced}))
	}
	return nil
}

// StopInstance stops the bundled instance.
func (c *Connector) StopInstance(ctx context.Context, actor string) error {
	if c.inst == nil {
		return packaging.Errf(contextforge.ReasonContextForgeDisabled, "the bundled instance is not configured")
	}
	c.instMu.Lock()
	defer c.instMu.Unlock()
	err := c.inst.Stop(ctx)
	if c.o.Recorder != nil {
		d := map[string]any{"actor": actor}
		if err != nil {
			d["error"] = err.Error()
		}
		if eerr := c.o.Recorder.Commit(c.instanceEvent("stopped", "", d)); eerr != nil && err == nil {
			err = eerr
		}
	}
	return err
}

// Instance returns the bundled instance's view.
func (c *Connector) Instance() InstanceView {
	lock := contextforge.ReleaseLock().ContextForge
	v := InstanceView{State: "disabled", Version: lock.Version, Image: lock.ImageRef("linux/" + runtime.GOARCH), Unconfined: !c.o.Enforced}
	switch {
	case !c.o.Config.ContextForge.Bundled:
	case c.instErr != nil:
		v.State, v.Detail, v.ReasonCode = "unavailable", c.instErr.Error(), packaging.ReasonOf(c.instErr)
	default:
		st := c.inst.Status()
		v.State, v.Detail, v.Restarts, v.StartedAt = st.State, st.Detail, st.Restarts, st.StartedAt
		if ver, _ := bundle.LoadVerification(c.dir); ver.Matches(&lock, c.platform) {
			v.Verified = ver.VerifiedAt.Format(time.RFC3339)
		}
	}
	return v
}

// HealthCauses are the non-critical health causes of the bundled instance
// (FR-22.25, FR-22.30): contextforge_unconfined while it runs outside the
// Enforced profile, contextforge_unhealthy while it does not answer.
func (c *Connector) HealthCauses() map[string]string {
	out := map[string]string{}
	if c.inst == nil {
		return out
	}
	st := c.inst.Status()
	if st.State == bundle.StateStopped {
		return out
	}
	if !c.o.Enforced {
		out["contextforge_unconfined"] = "the bundled ContextForge instance runs outside the Enforced profile, without the E-16 sandbox"
	}
	if st.State == bundle.StateUnhealthy {
		out["contextforge_unhealthy"] = "the bundled ContextForge instance does not answer /health: " + st.Detail
	}
	return out
}

// closeInstance stops the instance when the Gateway stops.
func (c *Connector) closeInstance() {
	if c.inst == nil || c.inst.Status().State == bundle.StateStopped {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.StopInstance(ctx, "E-36"); err != nil && !errors.Is(err, context.Canceled) {
		c.o.Log.Warn("stopping the bundled ContextForge instance", "error", err)
	}
}
