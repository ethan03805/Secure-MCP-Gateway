// Package policy is the policy model of the Policy Administration Service
// (E-05) and the evaluator of the Policy Decision Service (E-06): a
// schema-validated policy document (FR-3.2) compiled into an in-memory
// decision snapshot (FR-3.10), evaluated deterministically with default deny
// (SR-1.3-1), deny precedence (SR-1.4-1), a decision record (FR-3.11), rate
// and burst windows (FR-3.13, CP-11), per-session quotas, evaluation bounds
// (SR-1.20-1) and the restrict-only session taint obligation (SR-5.13-2).
// Two of the nine policy object types exist: Framework Profiles and Session
// Allow Policy Templates.
//
// The signed Policy Store (D-01) that holds published revisions is the
// policystore package; this package only validates, compiles, compares
// (Diff) and replays (Simulate) documents.
//
// The active snapshot is the policy authority. Replace swaps it atomically
// after validation; callers that must order the swap against in-flight
// launch authorizations (the Enforcement Coordinator) do so under their own
// barrier.
package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

//go:embed policy.schema.json
var schemaJSON []byte

// SchemaJSON returns the published policy schema.
func SchemaJSON() []byte { return append([]byte(nil), schemaJSON...) }

// SchemaVersion is the version of policy.schema.json; EvaluatorVersion is
// the version of the decision semantics in this file. Both are recorded with
// every published revision (FR-3.4).
const (
	SchemaVersion    = "1"
	EvaluatorVersion = "2"
)

var compiledSchema = func() *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		panic("embedded policy schema: " + err.Error())
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("policy.schema.json", doc); err != nil {
		panic(err)
	}
	s, err := c.Compile("policy.schema.json")
	if err != nil {
		panic("compile policy schema: " + err.Error())
	}
	return s
}()

// Document is the policy file as written.
type Document struct {
	Revision          string                      `json:"revision"`
	FrameworkProfiles map[string]FrameworkProfile `json:"framework_profiles"`
	Templates         map[string]Template         `json:"templates"`
}

// FrameworkProfile binds a framework instance to the templates it may use
// (ARCH §7.1 layer 2).
type FrameworkProfile struct {
	Templates       []string `json:"templates"`
	DefaultTemplate string   `json:"default_template"`
	CallsPerMinute  int      `json:"calls_per_minute,omitempty"`
}

// Template is a Session Allow Policy Template (ARCH §7.1 layer 3).
type Template struct {
	Description    string `json:"description,omitempty"`
	CallsPerMinute int    `json:"calls_per_minute,omitempty"`
	// CallsPerSession bounds the permitted calls of one session under this
	// template over its whole lifetime (quota state, ARCH §7.1 layer 5).
	CallsPerSession int `json:"calls_per_session,omitempty"`
	// TaintAction is what a tainted session gets for tools of a gated
	// side-effect class: "approve" (default) adds an approval obligation,
	// "deny" refuses the call (SR-5.13-2).
	TaintAction string `json:"taint_action,omitempty"`
	Rules       []Rule `json:"rules"`
}

// Rule permits (or, with effect "deny", forbids) the named backend tools of
// one server alias. Everything not named by a permit rule is denied, and a
// deny rule wins over every permit (SR-1.4-1). A deny rule may name "*" to
// cover every tool of the server. Filters names optional request and
// response filters (by filter ID) that must run on calls the rule permits;
// mandatory filters always run.
//
// SideEffect and SourceTrust classify the rule's tools for session taint.
// They combine with the verified manifest's classes restrict-only: the more
// restrictive side-effect class and "untrusted" over "trusted" win.
type Rule struct {
	ID              string   `json:"id"`
	Effect          string   `json:"effect,omitempty"`
	Server          string   `json:"server"`
	Tools           []string `json:"tools"`
	Approval        bool     `json:"approval,omitempty"`
	CallsPerMinute  int      `json:"calls_per_minute,omitempty"`
	CallsPerSession int      `json:"calls_per_session,omitempty"`
	SideEffect      string   `json:"side_effect,omitempty"`
	SourceTrust     string   `json:"source_trust,omitempty"`
	Filters         []string `json:"filters,omitempty"`
}

// Rule effects, taint actions, side-effect classes and source-trust values
// (CP-44).
const (
	EffectPermit = "permit"
	EffectDeny   = "deny"

	TaintApprove = "approve"
	TaintDeny    = "deny"

	SideRead     = "read"
	SideWrite    = "write"
	SideExternal = "external"
	SideExecute  = "execute"

	TrustTrusted   = "trusted"
	TrustUntrusted = "untrusted"

	// AnyTool is the wildcard a deny rule may use in tools.
	AnyTool = "*"
)

// Meta keys a verified ManifestSource (E-13) sets on a tool to carry the
// manifest's side-effect class and source trust. The edge reads them only
// from verified manifests; a live, unverified tool list cannot classify
// itself.
const (
	MetaSideEffect  = "local.smcpgw/sideEffect"
	MetaSourceTrust = "local.smcpgw/sourceTrust"
)

// Evaluation bounds (CP-12).
const (
	DefaultCandidateBound = 256
	DefaultDeadline       = 500 * time.Millisecond
)

// Snapshot is the compiled, immutable decision snapshot of one revision.
type Snapshot struct {
	Revision string
	Digest   string // SHA-256 of Raw
	Profiles map[string]FrameworkProfile
	// Raw is the canonical JSON of the document (keys sorted, no
	// insignificant whitespace). Digest and signatures cover these bytes.
	Raw []byte

	doc Document
	// grants[template][server][tool] -> permit rule
	grants map[string]map[string]map[string]*Rule
	// denies[template][server] -> deny rules
	denies map[string]map[string][]*Rule
	// rulesByTemplate keeps the declared order for considered-rule reporting.
	rulesByTemplate map[string][]*Rule
	templates       map[string]*Template
}

// Document returns a copy of the compiled document.
func (s *Snapshot) Document() Document {
	var d Document
	_ = json.Unmarshal(s.Raw, &d)
	return d
}

// Grant is one permitted (server, tool) pair of a template with its rule.
type Grant struct {
	Server string
	Tool   string
	Rule   *Rule
}

// Load reads and compiles the policy file.
func Load(path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := Compile(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Canonical returns the canonical JSON form of a JSON document: object keys
// sorted, numbers kept as written, no HTML escaping and no insignificant
// whitespace. Two documents with the same content have the same canonical
// bytes (FR-3.8).
func Canonical(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("parse: trailing data after the document")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Compile validates the document against the schema and the publication
// invariants that can be checked from the document alone (ARCH §7.3), then
// compiles it.
func Compile(raw []byte) (*Snapshot, error) {
	canon, err := Canonical(raw)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(canon, &generic); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := compiledSchema.Validate(generic); err != nil {
		return nil, fmt.Errorf("policy does not match schema: %w", err)
	}
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(canon))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	for name, p := range doc.FrameworkProfiles {
		found := false
		for _, t := range p.Templates {
			if _, ok := doc.Templates[t]; !ok {
				return nil, fmt.Errorf("framework profile %q names unknown template %q", name, t)
			}
			if t == p.DefaultTemplate {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("framework profile %q: default_template %q is not in its templates", name, p.DefaultTemplate)
		}
	}
	digest := sha256.Sum256(canon)
	s := &Snapshot{
		Revision:        doc.Revision,
		Digest:          hex.EncodeToString(digest[:]),
		Profiles:        doc.FrameworkProfiles,
		Raw:             canon,
		doc:             doc,
		grants:          map[string]map[string]map[string]*Rule{},
		denies:          map[string]map[string][]*Rule{},
		rulesByTemplate: map[string][]*Rule{},
		templates:       map[string]*Template{},
	}
	for tname := range doc.Templates {
		t := doc.Templates[tname]
		s.templates[tname] = &t
		byServer := map[string]map[string]*Rule{}
		denyByServer := map[string][]*Rule{}
		ruleIDs := map[string]bool{}
		for i := range t.Rules {
			r := &t.Rules[i]
			if ruleIDs[r.ID] {
				return nil, fmt.Errorf("template %q: duplicate rule id %q", tname, r.ID)
			}
			ruleIDs[r.ID] = true
			s.rulesByTemplate[tname] = append(s.rulesByTemplate[tname], r)
			if r.Effect == EffectDeny {
				if r.Approval || r.CallsPerMinute > 0 || r.CallsPerSession > 0 || len(r.Filters) > 0 || r.SideEffect != "" || r.SourceTrust != "" {
					return nil, fmt.Errorf("template %q: deny rule %q carries obligations or classes; a deny rule has none", tname, r.ID)
				}
				denyByServer[r.Server] = append(denyByServer[r.Server], r)
				continue
			}
			tools := byServer[r.Server]
			if tools == nil {
				tools = map[string]*Rule{}
				byServer[r.Server] = tools
			}
			for _, tool := range r.Tools {
				if tool == AnyTool {
					return nil, fmt.Errorf("template %q: permit rule %q uses %q; only deny rules may name every tool", tname, r.ID, AnyTool)
				}
				if prev, dup := tools[tool]; dup {
					// Overlapping permits are rejected at publication (SR-1.9-1).
					return nil, fmt.Errorf("template %q: rules %q and %q both permit %s/%s", tname, prev.ID, r.ID, r.Server, tool)
				}
				tools[tool] = r
			}
		}
		s.grants[tname] = byServer
		s.denies[tname] = denyByServer
	}
	return s, nil
}

// HasTemplate reports whether the snapshot defines the template.
func (s *Snapshot) HasTemplate(name string) bool { _, ok := s.grants[name]; return ok }

// denyRule returns the first deny rule of the template that covers the tool.
func (s *Snapshot) denyRule(template, server, tool string) *Rule {
	for _, r := range s.denies[template][server] {
		for _, t := range r.Tools {
			if t == tool || t == AnyTool {
				return r
			}
		}
	}
	return nil
}

// Grants lists every (server, tool) a template permits and no deny rule
// forbids, sorted.
func (s *Snapshot) Grants(template string) []Grant {
	var out []Grant
	for server, tools := range s.grants[template] {
		for tool, rule := range tools {
			if s.denyRule(template, server, tool) != nil {
				continue
			}
			out = append(out, Grant{server, tool, rule})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// Outcome of a decision.
const (
	Permit = "permit"
	Deny   = "deny"
)

// Reason codes (Appendix B data.reasonCode values produced by E-06).
const (
	ReasonPermit        = "PERMIT"
	ReasonNoPermit      = "NO_PERMIT" // SR-1.3-1
	ReasonNoTemplate    = "NO_TEMPLATE"
	ReasonDenyRule      = "DENY_RULE" // SR-1.4-1
	ReasonRateLimited   = "RATE_LIMITED"
	ReasonQuota         = "QUOTA_EXHAUSTED"
	ReasonEvalBound     = "EVAL_BOUND"  // SR-1.20-1
	ReasonNoSnapshot    = "NO_SNAPSHOT" // SR-1.2-1
	ReasonSessionState  = "SESSION_STATE"
	ReasonTaintDenied   = "TAINT_DENIED"   // SR-5.13-2
	ReasonTaintApproval = "TAINT_APPROVAL" // SR-5.13-2
)

// Obligations the evaluator can express (FR-3.12 subset).
type Obligations struct {
	Approval bool
	// ApprovalReason is the reason code to report when the approval
	// obligation is not satisfied: "" (APPROVAL_REQUIRED) or TAINT_APPROVAL.
	ApprovalReason string
	CallsPerMinute int
	Burst          int
	// CallsPerSession is the session quota that applied (0 when none).
	CallsPerSession int
	Filters         []string // optional filter IDs that must run
}

// Decision is the FR-3.11 record.
type Decision struct {
	ID              string
	Outcome         string
	ReasonCode      string
	ConsideredRules []string
	ApplicableRules []string
	DecisiveRules   []string
	Obligations     Obligations
	Route           string // server alias
	PolicyRevision  string
	Duration        time.Duration
	// SideEffect and SourceTrust are the effective classes of the tool
	// ("" when unclassified). Tainted reports that the session was tainted
	// when the decision was made; TaintsSession that releasing this call's
	// result taints the session (SR-5.13-2).
	SideEffect    string
	SourceTrust   string
	Tainted       bool
	TaintsSession bool
}

// Request is the canonical request subset E-06 evaluates.
type Request struct {
	PrincipalID string
	SessionID   string
	Profile     string // the principal's framework profile
	Template    string
	Server      string
	Tool        string
	// SideEffect and SourceTrust are the classes the verified manifest
	// declares for the tool ("" when the manifest is unverified or silent).
	SideEffect  string
	SourceTrust string
}

// Decider evaluates requests against the current snapshot and keeps the
// sliding-window rate counters of FR-3.13, the session quotas and the
// session taint marks.
type Decider struct {
	mu       sync.RWMutex
	snap     *Snapshot
	now      func() time.Time
	counters map[string][]time.Time
	defRate  int
	burst    int
	calls    int
	quota    map[string]map[string]int // session -> quota key -> permitted calls
	tainted  map[string]bool
	bound    int
	deadline time.Duration
	evalHook func() // tests: runs inside evaluation, before the deadline check
}

// NewDecider returns a decider with the given snapshot (may be nil, which
// denies everything with NO_SNAPSHOT) and CP-11 default principal rate.
func NewDecider(snap *Snapshot, defaultCallsPerMinute int) *Decider {
	return &Decider{snap: snap, now: time.Now, counters: map[string][]time.Time{}, defRate: defaultCallsPerMinute,
		quota: map[string]map[string]int{}, tainted: map[string]bool{}, bound: DefaultCandidateBound, deadline: DefaultDeadline}
}

// SetNow replaces the clock (tests).
func (d *Decider) SetNow(f func() time.Time) { d.mu.Lock(); d.now = f; d.mu.Unlock() }

// SetBurst sets the CP-11 burst: at most n calls in any window of
// n/limit minutes, for every rate window. 0 disables the burst window.
func (d *Decider) SetBurst(n int) { d.mu.Lock(); d.burst = n; d.mu.Unlock() }

// SetBounds replaces the CP-12 candidate-rule bound and decision deadline.
func (d *Decider) SetBounds(candidates int, deadline time.Duration) {
	d.mu.Lock()
	d.bound, d.deadline = candidates, deadline
	d.mu.Unlock()
}

// Snapshot returns the active snapshot.
func (d *Decider) Snapshot() *Snapshot { d.mu.RLock(); defer d.mu.RUnlock(); return d.snap }

// Activate swaps in a new snapshot atomically (FR-3.10) without checks.
// Prefer Replace.
func (d *Decider) Activate(s *Snapshot) { d.mu.Lock(); d.snap = s; d.mu.Unlock() }

// ErrRevisionReused is returned by Replace when a changed document keeps
// the active revision ID; catalogs and decisions are keyed by revision, so
// the revision must change whenever the content does.
var ErrRevisionReused = errors.New("policy content changed but the revision ID did not")

// Replace validates and activates a compiled snapshot. Reloading the same
// content is a no-op that reports unchanged.
func (d *Decider) Replace(s *Snapshot) (changed bool, err error) {
	if s == nil {
		return false, errors.New("nil snapshot")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.snap != nil && d.snap.Revision == s.Revision {
		if d.snap.Digest != s.Digest {
			return false, fmt.Errorf("%w (%s)", ErrRevisionReused, s.Revision)
		}
		return false, nil
	}
	d.snap = s
	return true, nil
}

// Taint marks a session tainted until it ends (SR-5.13-2). The edge calls
// it when a result from an untrusted-source tool is released.
func (d *Decider) Taint(sessionID string) {
	d.mu.Lock()
	d.tainted[sessionID] = true
	d.mu.Unlock()
}

// Tainted reports whether the session is tainted.
func (d *Decider) Tainted(sessionID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.tainted[sessionID]
}

// EndSession drops the taint mark and quota state of an ended session.
func (d *Decider) EndSession(sessionID string) {
	d.mu.Lock()
	delete(d.tainted, sessionID)
	delete(d.quota, sessionID)
	d.mu.Unlock()
}

var sideRank = map[string]int{SideRead: 0, SideWrite: 1, SideExternal: 2, SideExecute: 3}

// EffectiveSideEffect combines two side-effect classes restrict-only: the
// more restrictive one wins; "" is unknown.
func EffectiveSideEffect(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case sideRank[b] > sideRank[a]:
		return b
	}
	return a
}

// EffectiveSourceTrust combines two source-trust values restrict-only:
// "untrusted" wins over "trusted"; "" is unknown.
func EffectiveSourceTrust(a, b string) string {
	if a == TrustUntrusted || b == TrustUntrusted {
		return TrustUntrusted
	}
	if a == TrustTrusted || b == TrustTrusted {
		return TrustTrusted
	}
	return ""
}

// TaintGated reports whether a tool of side-effect class c is restricted in
// a tainted session. Unclassified tools are treated as gated, because the
// Gateway cannot show they do not write.
func TaintGated(c string) bool { return c != SideRead }

// Decide evaluates one request. It is deterministic given the snapshot, the
// counter state and the session's taint mark; it never consults anything
// else (SR-1.12-1).
func (d *Decider) Decide(req Request) Decision {
	start := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	dec := Decision{ID: ids.New(), Outcome: Deny}
	done := func() Decision { dec.Duration = time.Since(start); return dec }
	if d.snap == nil {
		dec.ReasonCode = ReasonNoSnapshot
		return done()
	}
	dec.PolicyRevision = d.snap.Revision
	tmpl := d.snap.templates[req.Template]
	if tmpl == nil {
		dec.ReasonCode = ReasonNoTemplate
		return done()
	}
	// Layer intersection (SR-1-2): the framework profile must still permit
	// the session's template under this revision.
	if req.Profile != "" {
		p, ok := d.snap.Profiles[req.Profile]
		if !ok || !slices.Contains(p.Templates, req.Template) {
			dec.ReasonCode = ReasonNoTemplate
			return done()
		}
	}
	candidates := 0
	for _, r := range d.snap.rulesByTemplate[req.Template] {
		dec.ConsideredRules = append(dec.ConsideredRules, r.ID)
		if r.Server == req.Server {
			candidates++
		}
	}
	if d.bound > 0 && candidates > d.bound { // SR-1.20-1
		dec.ReasonCode = ReasonEvalBound
		return done()
	}
	rule := d.snap.grants[req.Template][req.Server][req.Tool]
	deny := d.snap.denyRule(req.Template, req.Server, req.Tool)
	if rule != nil {
		dec.ApplicableRules = append(dec.ApplicableRules, rule.ID)
	}
	if deny != nil { // SR-1.4-1: deny wins regardless of permits
		dec.ApplicableRules = append(dec.ApplicableRules, deny.ID)
		dec.DecisiveRules = []string{deny.ID}
		dec.ReasonCode = ReasonDenyRule
		return done()
	}
	if rule == nil {
		dec.ReasonCode = ReasonNoPermit
		return done()
	}
	dec.DecisiveRules = []string{rule.ID}
	if BrokenBuild { // deliberate defect, smcp_broken builds only (FR-15.8)
		dec.Outcome, dec.ReasonCode, dec.Route = Permit, ReasonPermit, req.Server
		return done()
	}
	dec.SideEffect = EffectiveSideEffect(rule.SideEffect, req.SideEffect)
	dec.SourceTrust = EffectiveSourceTrust(rule.SourceTrust, req.SourceTrust)
	dec.TaintsSession = dec.SourceTrust == TrustUntrusted
	dec.Tainted = d.tainted[req.SessionID]

	ob := Obligations{Approval: rule.Approval, Filters: slices.Clone(rule.Filters)}
	// Session taint (SR-5.13-2): restrict-only, decided before any counter
	// is touched so that a refusal consumes nothing.
	if dec.Tainted && TaintGated(dec.SideEffect) {
		if tmpl.TaintAction == TaintDeny {
			dec.ReasonCode = ReasonTaintDenied
			return done()
		}
		if !ob.Approval {
			ob.Approval, ob.ApprovalReason = true, ReasonTaintApproval
		}
	}

	// Rate bound: the smallest applicable of rule, template, framework
	// profile and the CP-11 default, applied to the principal, session and
	// session-tool windows.
	limit := d.defRate
	for _, v := range []int{rule.CallsPerMinute, tmpl.CallsPerMinute, d.snap.Profiles[req.Profile].CallsPerMinute} {
		if v > 0 && v < limit {
			limit = v
		}
	}
	burst := d.burst
	if burst > limit {
		burst = limit
	}
	ob.CallsPerMinute, ob.Burst = limit, burst
	// Quota: the smallest of the rule's and the template's per-session
	// bounds, each counted in its own scope.
	type quotaKey struct {
		key   string
		limit int
	}
	var quotas []quotaKey
	if tmpl.CallsPerSession > 0 {
		quotas = append(quotas, quotaKey{"t:" + req.Template, tmpl.CallsPerSession})
	}
	if rule.CallsPerSession > 0 {
		quotas = append(quotas, quotaKey{"r:" + req.Template + "/" + rule.ID, rule.CallsPerSession})
	}
	for _, q := range quotas {
		if ob.CallsPerSession == 0 || q.limit < ob.CallsPerSession {
			ob.CallsPerSession = q.limit
		}
	}
	if d.evalHook != nil {
		d.evalHook()
	}
	if d.deadline > 0 && time.Since(start) > d.deadline { // SR-1.20-1
		dec.ReasonCode = ReasonEvalBound
		return done()
	}
	used := d.quota[req.SessionID]
	for _, q := range quotas {
		if used[q.key] >= q.limit {
			dec.ReasonCode = ReasonQuota
			dec.Obligations.CallsPerSession = ob.CallsPerSession
			return done()
		}
	}
	keys := []string{"p:" + req.PrincipalID, "s:" + req.SessionID, "t:" + req.SessionID + "/" + req.Server + "/" + req.Tool}
	if !d.allowLocked(keys, limit, burst) {
		dec.ReasonCode = ReasonRateLimited
		dec.Obligations.CallsPerMinute, dec.Obligations.Burst = limit, burst
		return done()
	}
	if len(quotas) > 0 {
		if used == nil {
			used = map[string]int{}
			d.quota[req.SessionID] = used
		}
		for _, q := range quotas {
			used[q.key]++
		}
	}
	dec.Outcome = Permit
	dec.ReasonCode = ReasonPermit
	dec.Obligations = ob
	dec.Route = req.Server
	return done()
}

// allowLocked applies a one-minute sliding window, and when burst > 0 a
// burst window of burst/limit minutes, to every key, and records the call
// in all of them only when every window has room, so a refused call
// consumes nothing.
func (d *Decider) allowLocked(keys []string, limit, burst int) bool {
	now := d.now()
	cut := now.Add(-time.Minute)
	var burstCut time.Time
	if burst > 0 && burst < limit {
		burstCut = now.Add(-time.Minute * time.Duration(burst) / time.Duration(limit))
	}
	d.calls++
	if d.calls%1024 == 0 {
		d.pruneLocked(cut)
	}
	ok := true
	for _, k := range keys {
		ts := d.counters[k]
		i := 0
		for i < len(ts) && !ts[i].After(cut) {
			i++
		}
		ts = ts[i:]
		d.counters[k] = ts
		if len(ts) >= limit {
			ok = false
		}
		if !burstCut.IsZero() {
			n := 0
			for j := len(ts) - 1; j >= 0 && ts[j].After(burstCut); j-- {
				n++
			}
			if n >= burst {
				ok = false
			}
		}
	}
	if !ok {
		return false
	}
	for _, k := range keys {
		d.counters[k] = append(d.counters[k], now)
	}
	return true
}

// pruneLocked drops windows with no call inside the last minute, so ended
// sessions do not keep counters forever.
func (d *Decider) pruneLocked(cut time.Time) {
	for k, ts := range d.counters {
		if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
			delete(d.counters, k)
		}
	}
}

// Counters returns the number of rate windows held (tests).
func (d *Decider) Counters() int { d.mu.RLock(); defer d.mu.RUnlock(); return len(d.counters) }
