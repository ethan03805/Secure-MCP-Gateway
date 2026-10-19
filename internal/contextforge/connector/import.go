package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Reason codes of the Connector's own refusals (docs/troubleshooting.md).
const (
	ReasonEntryUnsupported    = "CATALOG_ENTRY_UNSUPPORTED"
	ReasonImportKeyUnenrolled = "IMPORT_KEY_NOT_ENROLLED"
	ReasonProposalExpired     = "PROPOSAL_EXPIRED"
	ReasonDecisionMismatch    = "DECISION_TEXT_MISMATCH"
	ReasonHostedNotAvailable  = "HOSTED_IMPORT_UNAVAILABLE"
	ReasonProbeUnconfined     = "SANDBOXED_PROBE_UNAVAILABLE"
)

// Proposal states.
const (
	stateBuilding = "building"
	stateReady    = "ready"
	stateFailed   = "failed"
	stateDone     = "decided"
)

// LocalImport is the operator's input for importing a local entry
// (FR-22.6). The catalog names only a runner command, so the exact
// version, the artifact digest, the entry point and the licenses come from
// the operator.
type LocalImport struct {
	Version        string                  `json:"version"`
	ArtifactSHA256 string                  `json:"artifact_sha256,omitempty"`
	Integrity      string                  `json:"integrity,omitempty"`
	ArtifactType   string                  `json:"artifact_type,omitempty"` // default: proposed from install
	Package        string                  `json:"package,omitempty"`       // default: proposed from install
	Argv           []string                `json:"argv"`
	Runtime        string                  `json:"runtime,omitempty"`
	Licenses       []string                `json:"licenses"`
	Source         *packaging.RecipeSource `json:"source,omitempty"`
	RiskClass      string                  `json:"risk_class,omitempty"`  // default moderate
	SideEffect     string                  `json:"side_effect,omitempty"` // default external
}

// proposal is one import attempt between the request and the decision.
type proposal struct {
	ID            string    `json:"proposal_id"`
	EntryID       string    `json:"entry_id"`
	EntrySHA256   string    `json:"entry_sha256"`
	CatalogSHA256 string    `json:"catalog_sha256"`
	Class         string    `json:"class"`
	Actor         string    `json:"actor"`
	State         string    `json:"state"`
	Created       string    `json:"created"`
	Expires       string    `json:"expires,omitempty"`
	ReasonCode    string    `json:"reason_code,omitempty"`
	Error         string    `json:"error,omitempty"`
	Decision      *Decision `json:"decision,omitempty"`
	Outcome       string    `json:"outcome,omitempty"`
	ServerID      string    `json:"server_id,omitempty"`
	Revision      string    `json:"revision,omitempty"`

	created time.Time
	stage   string // <state>/contextforge/staging/<id>
}

// Decision is the trust decision presented to the operator (FR-22.12).
type Decision struct {
	Text   string    `json:"text"`
	SHA256 string    `json:"sha256"`
	Fields Presented `json:"fields"`
}

// Presented are the fields of a trust decision.
type Presented struct {
	Class        string   `json:"class"`
	Provider     string   `json:"provider"`
	URL          string   `json:"url,omitempty"`
	Repository   string   `json:"repository,omitempty"`
	AuthType     string   `json:"auth_type"`
	Artifact     string   `json:"artifact,omitempty"`
	Tools        []string `json:"tools"`
	RiskClass    string   `json:"risk_class"`
	SideEffects  []string `json:"side_effect_classes"`
	Egress       []string `json:"egress_destinations"`
	SecretSlots  []string `json:"secret_slots"`
	NotInspected bool     `json:"code_not_inspectable"`
}

func (p *proposal) view() proposal {
	v := *p
	if v.Decision != nil {
		d := *v.Decision
		v.Decision = &d
	}
	return v
}

func (c *Connector) entry(id string) (*contextforge.Entry, error) {
	if c.catErr != nil {
		return nil, c.catErr
	}
	e := c.cat.Entry(id)
	if e == nil {
		return nil, fmt.Errorf("%w: %q", contextforge.ErrUnknownEntry, id)
	}
	return e, nil
}

// ProposeLocal starts the import of a catalog entry: it checks the entry
// and the operator's pins, then builds the package in the background. The
// returned proposal is "building"; Proposal reports when it is "ready"
// with the trust decision or "failed". Every refusal records a
// catalog_import event.
func (c *Connector) ProposeLocal(id string, in LocalImport, actor string) (proposal, error) {
	e, err := c.entry(id)
	if err != nil {
		return proposal{}, err
	}
	class, reasons := e.Classify()
	now := c.o.Now()
	p := &proposal{ID: newID(), EntryID: e.ID, EntrySHA256: e.SHA256(), CatalogSHA256: c.cat.SHA256, Class: class,
		Actor: actor, State: stateBuilding, Created: now.UTC().Format(time.RFC3339), created: now}
	refuse := func(err error) (proposal, error) {
		p.State, p.ReasonCode, p.Error = stateFailed, packaging.ReasonOf(err), err.Error()
		if eerr := c.importEvent(p, "refused", p.ReasonCode, err.Error(), "", ""); eerr != nil {
			return proposal{}, eerr
		}
		return p.view(), err
	}
	switch class {
	case contextforge.ClassHosted:
		if !c.o.Config.ContextForge.Bundled {
			return refuse(packaging.Errf(contextforge.ReasonContextForgeDisabled,
				"hosted entry %s needs the bundled ContextForge instance, and [contextforge] bundled is false", e.ID))
		}
		return c.ProposeHosted(id, in, actor)
	case contextforge.ClassUnsupported:
		return refuse(packaging.Errf(ReasonEntryUnsupported, "entry %s is unsupported: %s", e.ID, strings.Join(reasons, "; ")))
	}
	r, err := c.recipe(e, in)
	if err != nil {
		return refuse(err)
	}
	if c.o.Confined && (c.o.Launcher == nil || !c.o.Launcher.Confined()) {
		return refuse(packaging.Errf(ReasonProbeUnconfined, "servers run in the sandbox here, and the Connector cannot sandbox the import probe yet; "+
			"build the recipe from smcpctl catalog import --dry-run with smcpctl package build --sandbox podman"))
	}
	p.stage = filepath.Join(c.dir, stagingDir, p.ID)
	if err := os.MkdirAll(p.stage, 0o700); err != nil {
		return refuse(err)
	}
	c.mu.Lock()
	c.proposals[p.ID] = p
	c.mu.Unlock()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.build(p, e, r)
	}()
	return p.view(), nil
}

// recipe turns the entry and the operator's pins into a packaging recipe.
// The install string is only read as text (FR-22.7).
func (c *Connector) recipe(e *contextforge.Entry, in LocalImport) (*packaging.Recipe, error) {
	prop := contextforge.ProposeArtifact(e.Install)
	typ, name := in.ArtifactType, in.Package
	if typ == "" {
		typ = prop.Type
	}
	if name == "" {
		name = prop.Name
	}
	if typ == "" || name == "" {
		return nil, packaging.Errf(packaging.ReasonUnpinned, "the install text %q does not name an artifact type and package; give artifact_type and package", e.Install)
	}
	ref := packaging.ArtifactRef{Type: typ, Name: name, Version: strings.TrimSpace(in.Version), SHA256: in.ArtifactSHA256, Integrity: in.Integrity}
	if err := ref.Check(); err != nil { // FR-22.6: FR-14.2 reasons for an unpinned reference
		return nil, err
	}
	if len(in.Licenses) == 0 {
		return nil, packaging.Errf(packaging.ReasonSourceEvidence, "licenses are required: the catalog has no license field")
	}
	risk := in.RiskClass
	if risk == "" {
		risk = "moderate"
	}
	if !slices.Contains(packaging.RiskClasses, risk) {
		return nil, packaging.Errf(packaging.ReasonManifestSchema, "risk class %q is not one of %v", risk, packaging.RiskClasses)
	}
	side := in.SideEffect
	if side == "" {
		side = "external"
	}
	rt := in.Runtime
	if rt == "" {
		rt = map[string]string{"npm": "node", "pypi": "python", "oci": "oci", "binary": "native"}[typ]
	}
	if err := packaging.CheckArgv(rt, in.Argv); err != nil {
		return nil, err
	}
	d, err := contextforge.DraftImport(c.cat, e.ID, contextforge.ImportOptions{Version: ref.Version, ArtifactSHA256: ref.SHA256})
	if err != nil {
		return nil, err
	}
	r := d.Recipe
	r.Artifact = ref
	r.Server.Revision = strings.TrimPrefix(ref.Version, "v") + fmt.Sprintf("+cf.%d", c.nextImport(e.ID))
	r.Launch = packaging.Launch{Runtime: rt, Argv: slices.Clone(in.Argv)}
	r.Licenses = slices.Clone(in.Licenses)
	r.RiskClass = risk
	r.Tools.Default = packaging.ToolClass{SideEffect: side, SourceTrust: "untrusted"}
	r.Source = in.Source
	r.SetDir(c.dir)
	return r, nil
}

func (c *Connector) nextImport(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.imports.forEntry(id)) + 1
}

// build runs packaging.Build for a proposal and prepares its decision.
func (c *Connector) build(p *proposal, e *contextforge.Entry, r *packaging.Recipe) {
	ctx, cancel := context.WithTimeout(context.Background(), c.o.BuildTimeout)
	defer cancel()
	out := filepath.Join(p.stage, "pkg")
	pkg, err := packaging.Build(ctx, r, out, packaging.BuildOptions{Fetcher: c.fetcher, Launcher: c.o.Launcher, Interp: c.o.Interp,
		Version: c.o.Version, Python: c.o.Interp.Python, Log: io.Discard, Now: c.o.Now()})
	if err == nil {
		err = packaging.Restate(out, func(pv *packaging.Provenance) error {
			pv.ContextForge = &packaging.ContextForgeOrigin{CatalogSHA256: c.cat.SHA256, ContextForgeRelease: c.cat.Release,
				EntryID: e.ID, EntrySHA256: e.SHA256(), Class: contextforge.ClassLocal, URL: e.URL, Repo: e.Repo, Install: e.Install}
			return nil
		})
	}
	var dec *Decision
	if err == nil {
		dec = decisionFor(e, c.cat, pkg.Manifest, p.Actor)
	}
	c.mu.Lock()
	if err != nil {
		p.State, p.ReasonCode, p.Error = stateFailed, packaging.ReasonOf(err), err.Error()
		if p.ReasonCode == "" {
			p.ReasonCode = packaging.ReasonProbeFailed
		}
	} else {
		p.State, p.Decision = stateReady, dec
		p.Expires = p.created.Add(ProposalTTL).UTC().Format(time.RFC3339)
	}
	c.mu.Unlock()
	if err != nil {
		_ = os.RemoveAll(p.stage)
		if eerr := c.importEvent(p, "refused", p.ReasonCode, err.Error(), "", ""); eerr != nil {
			c.o.Log.Error("contextforge import evidence", "error", eerr)
		}
	}
}

// decisionFor composes the trust decision text (FR-22.12). The text is
// what the operator accepts; its SHA-256 is recorded with the decision.
func decisionFor(e *contextforge.Entry, cat *contextforge.Catalog, m *packaging.Manifest, actor string) *Decision {
	f := Presented{Class: contextforge.ClassLocal, Provider: e.Provider, Repository: e.Repo, AuthType: e.AuthType,
		Artifact:  fmt.Sprintf("%s %s %s (sha256 %s)", m.Artifact.Type, m.Artifact.Reference, m.Artifact.Version, m.Artifact.SHA256),
		RiskClass: m.HighestRisk(), Tools: []string{}, SideEffects: []string{}, Egress: []string{}, SecretSlots: []string{}}
	sides := map[string]bool{}
	for _, t := range m.Tools {
		f.Tools = append(f.Tools, fmt.Sprintf("%s (%s, %s)", t.Name, t.SideEffect, t.SourceTrust))
		sides[t.SideEffect] = true
	}
	for s := range sides {
		f.SideEffects = append(f.SideEffects, s)
	}
	sort.Strings(f.SideEffects)
	for _, g := range m.Capabilities.Egress {
		f.Egress = append(f.Egress, fmt.Sprintf("%s ports %v", g.Host, g.Ports))
	}
	for _, s := range m.Secrets {
		f.SecretSlots = append(f.SecretSlots, fmt.Sprintf("%s (%s)", s.Slot, strings.Join(s.Modes, ", ")))
	}
	none := func(v []string) string {
		if len(v) == 0 {
			return "none"
		}
		return strings.Join(v, "; ")
	}
	release := cat.Release
	if release == "" {
		release = "operator-supplied catalog"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Import ContextForge catalog entry %s (%s) as %s@%s.\n", e.ID, e.Name, m.Server.ID, m.Server.Revision)
	fmt.Fprintf(&b, "Class: %s\nProvider: %s\nRepository: %s\nAuth type: %s\nArtifact: %s\n", f.Class, f.Provider, none(nonEmpty(f.Repository)), f.AuthType, f.Artifact)
	fmt.Fprintf(&b, "Risk class: %s\nTools (%d): %s\nSide-effect classes: %s\nEgress destinations: %s\nSecret slots: %s\n",
		f.RiskClass, len(m.Tools), none(f.Tools), none(f.SideEffects), none(f.Egress), none(f.SecretSlots))
	fmt.Fprintf(&b, "Catalog: sha256 %s (%s); entry sha256 %s.\n", cat.SHA256, release, e.SHA256())
	fmt.Fprintf(&b, "The catalog states no version, digest, license or signer for this server; the artifact above is the one you pinned. "+
		"Accepting signs the package with this Gateway's catalog import key as %s's decision. ContextForge and IBM have not reviewed this server. "+
		"The package is imported disabled and no policy grant changes.\n", actor)
	text := b.String()
	sum := sha256.Sum256([]byte(text))
	return &Decision{Text: text, SHA256: hex.EncodeToString(sum[:]), Fields: f}
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// Proposal returns one proposal.
func (c *Connector) Proposal(id string) (proposal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.proposals[id]
	if !ok {
		return proposal{}, false
	}
	return p.view(), true
}

// Proposals returns every proposal, newest first.
func (c *Connector) Proposals() []proposal {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]proposal, 0, len(c.proposals))
	for _, p := range c.proposals {
		out = append(out, p.view())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Created > out[j].Created || (out[i].Created == out[j].Created && out[i].ID > out[j].ID)
	})
	return out
}

// DecisionError is a refused decision request that leaves the proposal
// waiting.
type DecisionError struct{ Code, Msg string }

func (e *DecisionError) Error() string { return e.Code + ": " + e.Msg }

// Decide applies the operator's trust decision to a ready proposal
// (FR-22.12). A decline records the decision and removes the built package.
// An accept must name the SHA-256 of the presented text; the Connector then
// records the decision in the provenance statement, signs the package with
// the catalog import key and imports it verified-disabled (FR-22.13).
func (c *Connector) Decide(id string, accept bool, presented, actor string) (proposal, error) {
	c.mu.Lock()
	p, ok := c.proposals[id]
	if !ok {
		c.mu.Unlock()
		return proposal{}, &DecisionError{Code: "not_found", Msg: "no proposal " + id}
	}
	if p.State != stateReady {
		st := p.State
		c.mu.Unlock()
		return proposal{}, &DecisionError{Code: "not_ready", Msg: "proposal " + id + " is " + st}
	}
	if accept {
		if !strings.EqualFold(strings.TrimSpace(presented), p.Decision.SHA256) {
			c.mu.Unlock()
			return proposal{}, &DecisionError{Code: ReasonDecisionMismatch, Msg: "presented_sha256 must be the SHA-256 of the decision text shown (" + p.Decision.SHA256 + ")"}
		}
		if ok, classes := c.keyEnrolled(); !ok || !slices.Contains(classes, p.Decision.Fields.RiskClass) {
			c.mu.Unlock()
			return proposal{}, &DecisionError{Code: ReasonImportKeyUnenrolled, Msg: fmt.Sprintf("the catalog import key %s is not an enrolled trust anchor for risk class %s; an Administrator enrolls it with smcpctl trust add (see smcpctl catalog status)", c.KeyID(), p.Decision.Fields.RiskClass)}
		}
	}
	p.State = stateDone
	c.mu.Unlock()

	now := c.o.Now().UTC().Format(time.RFC3339)
	outcome := "declined"
	if accept {
		outcome = "accepted"
	}
	if err := c.event(ClassTrustDecision, outcome, "", "", map[string]any{"entry_id": p.EntryID, "entry_sha256": p.EntrySHA256,
		"class": p.Class, "catalog_sha256": p.CatalogSHA256, "actor": actor, "presented_sha256": p.Decision.SHA256,
		"proposal_id": p.ID, "decision": outcome}); err != nil {
		c.setDone(p, outcome, "", "")
		_ = os.RemoveAll(p.stage)
		return p.view(), err
	}
	if !accept {
		_ = os.RemoveAll(p.stage)
		c.setDone(p, "declined", "", "")
		return p.view(), c.importEvent(p, "declined", "", "trust decision declined by "+actor, "", "")
	}
	serverID, rev, err := c.signAndImport(p, actor, now)
	_ = os.RemoveAll(p.stage)
	if err != nil {
		c.setDone(p, "refused", "", "")
		p.ReasonCode, p.Error = packaging.ReasonOf(err), err.Error()
		if eerr := c.importEvent(p, "refused", p.ReasonCode, err.Error(), "", ""); eerr != nil {
			return p.view(), eerr
		}
		return p.view(), err
	}
	c.mu.Lock()
	aerr := c.imports.add(importRecord{EntryID: p.EntryID, EntrySHA256: p.EntrySHA256, CatalogSHA256: p.CatalogSHA256, Class: p.Class,
		ServerID: serverID, Revision: rev, Actor: actor, Time: now})
	c.mu.Unlock()
	c.setDone(p, "imported", serverID, rev)
	if err := c.importEvent(p, "imported", "", "", serverID, rev); err != nil {
		return p.view(), err
	}
	return p.view(), aerr
}

func (c *Connector) setDone(p *proposal, outcome, serverID, rev string) {
	c.mu.Lock()
	p.Outcome, p.ServerID, p.Revision = outcome, serverID, rev
	c.mu.Unlock()
}

func (c *Connector) signAndImport(p *proposal, actor, now string) (string, string, error) {
	dir := filepath.Join(p.stage, "pkg")
	td := &packaging.TrustDecision{Actor: actor, Time: now, PresentedSHA256: p.Decision.SHA256, Text: p.Decision.Text}
	if err := packaging.Restate(dir, func(pv *packaging.Provenance) error { pv.TrustDecision = td; return nil }); err != nil {
		return "", "", err
	}
	if err := packaging.Sign(dir, c.key, c.o.Now()); err != nil {
		return "", "", err
	}
	pkg, err := packaging.Verify(dir, packaging.VerifyOptions{Keys: c.resolver(), Now: c.o.Now()})
	if err != nil {
		return "", "", err
	}
	dst := filepath.Join(c.o.Library.Dir(), pkg.Index.ServerID, pkg.Index.Revision)
	if err := packaging.CopyPackage(dir, dst); err != nil {
		return "", "", err
	}
	rc, err := c.o.Library.Import(dst, library.ImportOptions{Actor: actor})
	if err != nil {
		_ = os.RemoveAll(dst)
		return "", "", err
	}
	return rc.ServerID, rc.Revision, nil
}

func (c *Connector) resolver() packaging.KeyResolver {
	pub, _ := packaging.ParsePublicKey(c.pub)
	return packaging.PublicKeyResolver(pub)
}
