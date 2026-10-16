// Package edge is the Harness Edge (E-01 Harness Interface Endpoint, E-02
// Protocol Mediator) together with the Access Enforcement Point (E-08) and
// Enforcement Coordinator (E-12) that a tool call passes through.
//
// The MCP wire protocol for both eras comes from the MCP Go SDK's
// StreamableHTTPHandler in stateless mode (see spikes/go-sdk-dual-era). One
// mcp.Server exists per Gateway session; it holds exactly the tools the
// session's policy permits (SR-5.4-1, SR-5.7-1) and every call runs the
// pipeline of FR-4.3 in order (pipeline.go). The stages that later elements
// provide are reached through the seams of internal/pipeline.
//
// Barrier: launch authorization and release authorization run under the
// read side of Gateway.gate; emergency stop, resume and policy activation
// take the write side. A state change therefore waits for authorizations in
// progress and every authorization sees one consistent state.
package edge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Appendix B Gateway error codes.
const (
	CodePolicyDenied      = -31001
	CodeApprovalRequired  = -31002
	CodeResponseWithheld  = -31003
	CodeGatewayFailClosed = -31004
	CodeRateLimited       = -31005
	CodeSessionInvalid    = -31006
	CodeBackendError      = -31007
	CodeTimeout           = -31008
	CodeIndeterminate     = -31009
)

// Reason codes the edge produces itself.
const (
	ReasonAuditUnavailable = "AUDIT_UNAVAILABLE"
	ReasonFailClosed       = "FAIL_CLOSED"
	ReasonEmergencyStop    = "EMERGENCY_STOP"
	ReasonCapability       = "CAPABILITY_INVALID"
	ReasonSessionState     = "SESSION_STATE"
	ReasonSessionEnded     = "SESSION_ENDED"
	ReasonApprovalDenied   = "APPROVAL_DENIED"
	ReasonApprovalNoSvc    = "APPROVAL_UNAVAILABLE"
	ReasonRevisionChanged  = "POLICY_REVISION_CHANGED"
)

// Supported northbound protocol versions (CP-04).
var ProtocolVersions = []string{"2026-07-28", "2025-11-25"}

const metaPrefix = "local.smcpgw/"

// Meta keys set on presented tools that carry an approval obligation:
// Claude Code's key (FR-1.50) and a vendor-neutral key for other clients.
const (
	MetaRequiresUserInteraction = "anthropic/requiresUserInteraction"
	MetaApprovalRequired        = metaPrefix + "approvalRequired"
)

// Deps are the components a Gateway is built over. Evidence, Store, OAuth,
// Decider and Registry are required; the seams default to the current
// behavior.
type Deps struct {
	Config   *config.Config
	Store    *session.Store
	OAuth    *session.OAuth
	Decider  *policy.Decider
	Registry *backend.Registry
	Evidence audit.Recorder
	// EvidenceErr reports a sticky evidence failure (the journal's Err);
	// when it returns non-nil the Gateway is fail-closed.
	EvidenceErr func() error
	Log         *slog.Logger

	Profile      profile.Report
	Approver     pipeline.Approver
	Filters      *pipeline.Filters
	Capabilities *pipeline.Capabilities
	// ConsoleURL is the base URL approval deep links point at.
	ConsoleURL string
}

// Gateway wires the slice together.
type Gateway struct {
	cfg         *config.Config
	store       *session.Store
	oauth       *session.OAuth
	decider     *policy.Decider
	reg         *backend.Registry
	evidence    audit.Recorder
	evidenceErr func() error
	log         *slog.Logger
	prof        profile.Report
	approver    pipeline.Approver
	filters     *pipeline.Filters
	caps        *pipeline.Capabilities
	consoleURL  string

	gate    sync.RWMutex // launch/release barrier (see package comment)
	stopped atomic.Bool  // FR-4.14 emergency stop
	mux     *http.ServeMux
	handler *mcp.StreamableHTTPHandler

	mu      sync.Mutex
	servers map[string]*sessionServer
	track   *tracker // in-flight requests, calls and listen streams per session
}

type sessionServer struct {
	revision string
	srv      *mcp.Server
}

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxCorrelation
)

// New builds the Gateway over already-started components.
func New(d Deps) (*Gateway, error) {
	if d.Config == nil || d.Store == nil || d.OAuth == nil || d.Decider == nil || d.Registry == nil || d.Evidence == nil {
		return nil, errors.New("edge: config, store, oauth, decider, registry and evidence are required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.EvidenceErr == nil {
		d.EvidenceErr = func() error { return nil }
	}
	if d.Approver == nil {
		d.Approver = pipeline.RefuseApprover{}
	}
	if d.Filters == nil {
		d.Filters = pipeline.NewFilters()
	}
	if d.Capabilities == nil {
		return nil, errors.New("edge: the capability ledger shared with the dispatcher is required")
	}
	if d.Profile.Profile == "" {
		d.Profile = profile.Report{Profile: profile.Standalone, Label: "not enforced", Reasons: []string{"profile not resolved"}}
	}
	g := &Gateway{cfg: d.Config, store: d.Store, oauth: d.OAuth, decider: d.Decider, reg: d.Registry, evidence: d.Evidence,
		evidenceErr: d.EvidenceErr, log: d.Log, prof: d.Profile, approver: d.Approver, filters: d.Filters, caps: d.Capabilities,
		consoleURL: d.ConsoleURL, servers: map[string]*sessionServer{}, track: newTracker()}
	g.handler = mcp.NewStreamableHTTPHandler(g.serverFor, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true,                             // FR-1.6: JSON unless the request needs a stream
		MaxRequestBodyBytes: d.Config.Limits.RequestBodyBytes, // CP-07, before parsing (SR-7.11-1)
		Logger:              d.Log,
	})
	g.mux = http.NewServeMux()
	d.OAuth.Register(g.mux)
	g.mux.Handle(d.Config.Listener.MCPPath, g.mcpChain(g.handler))
	g.mux.HandleFunc("GET /healthz", g.healthz)
	d.Store.OnEnd(g.sessionEnded)
	return g, nil
}

// Handler returns the harness listener's HTTP handler (host and origin
// checks apply to every path).
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.hostAllowed(r) { // SR-2.9-2
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !g.originAllowed(o) { // SR-2.9-1
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		g.mux.ServeHTTP(w, r)
	})
}

func (g *Gateway) hostAllowed(r *http.Request) bool {
	host := r.Host
	if u, err := url.Parse(g.cfg.Listener.PublicURL); err == nil && strings.EqualFold(host, u.Host) {
		return true
	}
	return strings.EqualFold(host, g.cfg.Listener.Address)
}

func (g *Gateway) originAllowed(origin string) bool {
	for _, o := range g.cfg.Listener.AllowedOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

// TLSConfig is the SR-2.8-1 profile: TLS 1.3 only.
func TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, nil
}

// CheckLoopback refuses a listener address that is not loopback (SR-2.9-3).
func CheckLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); (ip == nil && host != "localhost") || (ip != nil && !ip.IsLoopback()) {
		return fmt.Errorf("listener %q is not loopback (SR-2.9-3)", addr)
	}
	return nil
}

// ServeTLS runs an HTTP server with the listener limits of CP-06 and CP-07
// on ln until ctx ends.
func ServeTLS(ctx context.Context, ln net.Listener, h http.Handler, tc *tls.Config, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         tc,
		ReadHeaderTimeout: 5 * time.Second,  // CP-06
		ReadTimeout:       15 * time.Second, // CP-07
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10, // CP-06
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}

// Listen opens the harness listener after the loopback check.
func (g *Gateway) Listen() (net.Listener, error) {
	if err := CheckLoopback(g.cfg.Listener.Address); err != nil {
		return nil, err
	}
	return net.Listen("tcp", g.cfg.Listener.Address)
}

// Serve runs the harness TLS listener on ln until ctx ends.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error {
	tc, err := TLSConfig(g.cfg.Listener.TLSCert, g.cfg.Listener.TLSKey)
	if err != nil {
		return err
	}
	return ServeTLS(ctx, ln, g.Handler(), tc, g.log)
}

// RunJanitors prunes expired sessions, authorization codes and launch
// capabilities until ctx ends.
func (g *Gateway) RunJanitors(ctx context.Context, interval time.Duration) {
	go g.store.Run(ctx, interval)
	go g.oauth.Run(ctx, interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.caps.Prune()
		}
	}
}

// ErrAuditUnavailable is returned by administrative actions whose evidence
// could not be written.
var ErrAuditUnavailable = errors.New("evidence journal unavailable")

func adminEvent(class, outcome, reason, actor string, detail map[string]any) audit.Event {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["actor"] = actor
	return audit.Event{Class: class, Origin: "E-24", Outcome: outcome, ReasonCode: reason, PolicyStatus: "not_evaluated", Detail: detail}
}

// Stop enters the emergency-stop state (FR-4.14). The state changes even
// when the evidence write fails, because stopping is the safe direction;
// the error is still returned so the caller can report it.
func (g *Gateway) Stop(actor, reason string) error {
	g.gate.Lock()
	g.stopped.Store(true)
	g.gate.Unlock()
	g.log.Warn("emergency stop", "actor", actor, "reason", reason)
	if err := g.evidence.Commit(adminEvent("admin", "stopped", ReasonEmergencyStop, actor, map[string]any{"reason": reason})); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// Resume leaves the emergency-stop state. Resume is refused when its
// evidence cannot be written (fail closed).
func (g *Gateway) Resume(actor string) error {
	g.gate.Lock()
	defer g.gate.Unlock()
	if err := g.evidence.Commit(adminEvent("admin", "resumed", "EMERGENCY_RESUME", actor, nil)); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	g.stopped.Store(false)
	g.log.Warn("emergency stop lifted", "actor", actor)
	return nil
}

// Stopped reports the emergency-stop state.
func (g *Gateway) Stopped() bool { return g.stopped.Load() }

// ActivatePolicy validates and activates a compiled snapshot under the
// barrier (FR-3.10) and records the change. Session catalogs are rebuilt on
// their next request.
func (g *Gateway) ActivatePolicy(actor string, snap *policy.Snapshot) (bool, error) {
	g.gate.Lock()
	defer g.gate.Unlock()
	prev := ""
	if cur := g.decider.Snapshot(); cur != nil {
		prev = cur.Revision
	}
	if cur := g.decider.Snapshot(); cur != nil && cur.Revision == snap.Revision {
		if cur.Digest != snap.Digest {
			return false, fmt.Errorf("%w (%s)", policy.ErrRevisionReused, snap.Revision)
		}
		return false, nil
	}
	if err := g.evidence.Commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "activated", ReasonCode: "POLICY_ACTIVATED", PolicyRevision: snap.Revision,
		PolicyStatus: "not_evaluated", Detail: map[string]any{"actor": actor, "previous_revision": prev, "digest": snap.Digest}}); err != nil {
		return false, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return g.decider.Replace(snap)
}

// failClosed reports why MCP requests must be refused, or "" (FR-9.17,
// SR-1.2-1, FR-4.14).
func (g *Gateway) failClosed() string {
	switch {
	case g.stopped.Load():
		return ReasonEmergencyStop
	case g.decider.Snapshot() == nil:
		return policy.ReasonNoSnapshot
	case g.evidenceErr() != nil:
		return ReasonAuditUnavailable
	}
	return ""
}

// Health is the Gateway's health report.
type Health struct {
	State          string   `json:"state"` // healthy, degraded, fail-closed
	Causes         []string `json:"causes"`
	Profile        string   `json:"profile"`
	ReleaseLabel   string   `json:"release_label"`
	ProfileReasons []string `json:"profile_reasons,omitempty"`
	Version        string   `json:"version"`
	PolicyRevision string   `json:"policy_revision,omitempty"`
	Sessions       int      `json:"sessions"`
	Launcher       string   `json:"launcher"`
	Servers        []string `json:"servers"`
	Unverified     []string `json:"unverified_servers,omitempty"`
}

// Health computes the health report.
func (g *Gateway) Health() Health {
	h := Health{State: "healthy", Causes: []string{}, Profile: g.prof.Profile, ReleaseLabel: g.prof.Label, ProfileReasons: g.prof.Reasons,
		Version: backend.Version, Sessions: len(g.store.Active()), Launcher: g.reg.Launcher().Name(), Servers: []string{}}
	if c := g.prof.Degraded(); c != "" {
		h.State, h.Causes = "degraded", append(h.Causes, c)
	}
	for alias, s := range g.reg.Servers() {
		h.Servers = append(h.Servers, alias)
		if !s.Verified {
			h.Unverified = append(h.Unverified, alias)
		}
	}
	if len(h.Unverified) > 0 {
		h.State, h.Causes = "degraded", append(h.Causes, "unverified_manifests")
	}
	if g.stopped.Load() {
		h.State, h.Causes = "fail-closed", append(h.Causes, "emergency_stop")
	}
	if snap := g.decider.Snapshot(); snap == nil {
		h.State, h.Causes = "fail-closed", append(h.Causes, "no_decision_snapshot")
	} else {
		h.PolicyRevision = snap.Revision
	}
	if g.evidenceErr() != nil {
		h.State, h.Causes = "fail-closed", append(h.Causes, "evidence_unavailable")
	}
	return h
}

// healthz is the unauthenticated harness-listener health endpoint. It
// reports state, causes and profile only; the control API has the detail.
func (g *Gateway) healthz(w http.ResponseWriter, r *http.Request) {
	h := g.Health()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if h.State == "fail-closed" {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"state": h.State, "causes": h.Causes, "profile": h.Profile, "release_label": h.ReleaseLabel, "version": h.Version})
}

// gatewayError builds an Appendix B error with FR-1.20 data.
func gatewayError(code int64, msg, reason, correlation, decision string, extra map[string]any) *jsonrpc.Error {
	data := map[string]any{"reasonCode": reason, "correlationId": correlation}
	if decision != "" {
		data["decisionId"] = decision
	}
	for k, v := range extra {
		data[k] = v
	}
	raw, _ := json.Marshal(data)
	return &jsonrpc.Error{Code: code, Message: msg, Data: raw}
}

func writeRPCError(w http.ResponseWriter, status int, e *jsonrpc.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": e})
}

// mcpChain is the E-01/E-03 front of the MCP endpoint.
func (g *Gateway) mcpChain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { // FR-1.3
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		corr := ids.New() // FR-4.2
		if reason := g.failClosed(); reason != "" {
			writeRPCError(w, http.StatusServiceUnavailable, gatewayError(CodeGatewayFailClosed, "gateway fail-closed", reason, corr, "", nil))
			return
		}
		sess, err := g.store.Authenticate(session.Bearer(r), "tls") // FR-2.5, SR-2.1-3
		if err != nil {
			if aerr := g.evidence.Commit(audit.Event{Class: "auth_failure", Origin: "E-03", CorrelationID: corr, Outcome: "deny", ReasonCode: "SESSION_INVALID", PolicyStatus: "not_evaluated"}); aerr != nil {
				g.log.Error("evidence write failed", "err", aerr)
			}
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, g.oauth.ResourceMetadataURL()))
			writeRPCError(w, http.StatusUnauthorized, gatewayError(CodeSessionInvalid, "session invalid", "SESSION_INVALID", corr, "", nil))
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		kind := kindRequest
		if r.Header.Get("Mcp-Method") == "subscriptions/listen" {
			kind = kindListen
		}
		defer g.track.add(sess.ID, kind, cancel)()
		ctx = context.WithValue(ctx, ctxSession, sess)
		ctx = context.WithValue(ctx, ctxCorrelation, corr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// trackCall registers a call's cancel function under its session so that
// ending the session cancels it (FR-2.11). It returns the unregister func.
func (g *Gateway) trackCall(sessionID string, cancel context.CancelFunc) func() {
	return g.track.add(sessionID, kindCall, cancel)
}

// InFlight returns the number of tool calls in progress (tests and health).
func (g *Gateway) InFlight() int { return g.track.count(kindCall) }

// ListenStreams returns the number of open listen streams.
func (g *Gateway) ListenStreams() int { return g.track.count(kindListen) }

// sessionEndGrace bounds how long ending a session waits for its requests
// to write their responses before closing its MCP sessions.
const sessionEndGrace = 3 * time.Second

// sessionEnded cancels the session's in-flight calls and listen streams,
// lets its requests finish writing, then drops its server and closes its
// MCP sessions (FR-2.11).
func (g *Gateway) sessionEnded(s session.Session) {
	g.mu.Lock()
	ss := g.servers[s.ID]
	delete(g.servers, s.ID)
	g.mu.Unlock()
	cancelled := g.track.endSession(s.ID, sessionEndGrace)
	if ss != nil {
		for ms := range ss.srv.Sessions() {
			_ = ms.Close()
		}
	}
	if err := g.evidence.Commit(audit.Event{Class: "session", Origin: "E-04", SessionID: s.ID, PrincipalID: s.PrincipalID, Outcome: s.State, ReasonCode: s.EndReason, PolicyStatus: "not_evaluated",
		Detail: map[string]any{"cancelled_calls": cancelled}}); err != nil {
		g.log.Error("evidence write failed", "err", err)
	}
}

// Close releases resources.
func (g *Gateway) Close() {
	g.mu.Lock()
	servers := g.servers
	g.servers = map[string]*sessionServer{}
	g.mu.Unlock()
	for _, ss := range servers {
		for ms := range ss.srv.Sessions() {
			_ = ms.Close()
		}
	}
}
