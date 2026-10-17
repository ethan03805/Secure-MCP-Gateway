// Package backend is the slice of the Local Server Registry (E-14), Server
// Runtime Manager (E-15) and Tool Dispatcher (E-10): it launches each
// configured MCP server through a pipeline.Launcher, takes its tool
// definitions from a pipeline.ManifestSource, derives public tool names
// (FR-1.26, FR-1.49, FR-5.22) and dispatches calls with the CP-10
// concurrency bounds and FIFO queue (FR-4.8), the CP-13 upstream timeout
// (FR-4.9), bounded buffering (FR-4.10), backend error mapping (FR-1.32)
// and a one-use launch capability check before anything reaches a backend
// (FR-4.13).
//
// Result size: every line the server writes is bounded while it is read
// (see frameFilter), so a backend cannot make the Gateway buffer more than
// CP-08 plus a small envelope allowance for one message. An oversized
// response is replaced by an error for the same request ID and reported as
// ErrTooLarge. Residual: when the request ID appears only after the first
// CP-08 bytes of the line, the response cannot be matched; it is dropped
// and the call ends at the upstream timeout as indeterminate.
//
// Protocol screening (frameFilter): server-initiated requests other than
// ping are answered with -32601 (FR-5.20), an InputRequiredResult becomes
// ErrInputRequired (FR-5.24), and progress is routed to the owning call in
// line order (FR-1.39). No client capability is declared southbound
// (SR-5.6-2). An instance that times out or fails is replaced (restart).
// A line that is not one UTF-8 JSON-RPC 2.0 message ends the connection
// (ErrInvalidOutput, FR-5.13, FR-5.14); a result with an unrecognized
// resultType or that does not decode as a CallToolResult is ErrInvalidResult
// (FR-5.23, SR-5.20-1); an instance that ends after dispatch is
// ErrInstanceFailed and the call is not retried (SR-7.2-1).
//
// Era: the handshake is initialize with 2025-11-25 (FR-5.19); the
// 2026-07-28 probe is deferred (SRS Appendix N). The negotiated version is
// handed to the ManifestSource in ServerSpec.NegotiatedEra (FR-5.40).
//
// Not in this slice: signed packages (E-13 provides a verified
// ManifestSource), sandboxing (E-16 provides a confined Launcher), runtime
// monitoring (E-17) and egress brokering (E-18). Instances are shared (one
// per server), not per session.
package backend

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Limits are the CP values the dispatcher enforces.
type Limits struct {
	PerPrincipal    int
	Total           int
	Queue           int // calls that may wait for a slot; 0 means none wait
	UpstreamTimeout time.Duration
	ResultBytes     int64
	StderrBytes     int
}

// Options wire the registry's seams. Zero values take the defaults:
// SubprocessLauncher, LiveManifest and NoSecrets. Capabilities is required.
type Options struct {
	Limits       Limits
	Launcher     pipeline.Launcher
	Manifests    pipeline.ManifestSource
	Secrets      pipeline.SecretBroker
	Capabilities pipeline.CapabilityChecker
	Log          *slog.Logger
}

// Server is one launched backend instance with its recorded revision.
type Server struct {
	Alias          string
	Revision       string
	Era            string // protocol version negotiated by the SDK client
	Tools          []*mcp.Tool
	Verified       bool   // tool definitions come from a verified manifest
	ManifestSource string // "live" when unverified
	cfg            config.Server
	spec           pipeline.ServerSpec
	suspended      atomic.Bool

	// mu guards cur and ready. ready is nil or closed while cur may be
	// used; a restart replaces it with an open channel until the new
	// instance is up, so calls wait instead of reaching the instance being
	// replaced.
	mu       sync.Mutex
	cur      *instance
	ready    chan struct{}
	restarts atomic.Uint64
}

// instance is one running process of a server and its MCP client session.
type instance struct {
	session *mcp.ClientSession
	proc    pipeline.Process
	filter  *frameFilter
	live    pipeline.LiveLister
	started atomic.Bool // tool set established; list_changed is acted on
}

func (in *instance) close() {
	if in != nil && in.session != nil {
		_ = in.session.Close()
	}
}

// current returns the instance in use, waiting while a restart is under
// way. It returns nil when the server has no instance.
func (s *Server) current(ctx context.Context) (*instance, error) {
	s.mu.Lock()
	ready := s.ready
	s.mu.Unlock()
	if ready != nil {
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur, nil
}

// peek returns the instance without waiting for a restart.
func (s *Server) peek() *instance {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Restarts returns how many times the instance was replaced after an
// upstream timeout or a failed instance (Appendix L HF-17, HF-19).
func (s *Server) Restarts() uint64 { return s.restarts.Load() }

// ToolRef resolves a public name to its backend (FR-1.29).
type ToolRef struct {
	Public   string
	Server   *Server
	Tool     *mcp.Tool
	Revision string // tool revision: server revision + "/" + tool name
}

// Registry holds launched servers and the public-name index.
type Registry struct {
	limits   Limits
	launcher pipeline.Launcher
	caps     pipeline.CapabilityChecker
	log      *slog.Logger
	watcher  pipeline.ManifestWatcher // nil unless the ManifestSource watches list_changed
	opts     Options

	// progress routes backend notifications/progress to the call that
	// owns the Gateway-issued token (FR-1.39).
	progress sync.Map // token string -> func(*mcp.ProgressNotificationParams)
	progSeq  atomic.Uint64

	smu      sync.RWMutex // guards servers, tools, public and disabled
	servers  map[string]*Server
	tools    map[string]*ToolRef
	public   []string
	disabled map[string]string // alias -> reason the revision was not enabled

	mu       sync.Mutex // guards perPrinc and waiting
	perPrinc map[string]*fifo
	total    *fifo
	waiting  int
	inFlight sync.WaitGroup
}

var publicPart = regexp.MustCompile(`[^A-Za-z0-9_]`)

// PublicName derives the CP-42 public name (FR-1.26).
func PublicName(alias, tool string) string {
	return alias + "_" + publicPart.ReplaceAllString(tool, "_")
}

var propName = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// CheckToolDefinition applies the FR-5.22 drift rules to a live tool. The
// x-mcp-header annotation rules are not checked yet.
func CheckToolDefinition(t *mcp.Tool) error {
	if t.InputSchema == nil {
		return errors.New("inputSchema is null")
	}
	raw, err := json.Marshal(t.InputSchema)
	if err != nil {
		return fmt.Errorf("inputSchema not serializable: %w", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return errors.New("inputSchema is not an object")
	}
	if props, ok := schema["properties"].(map[string]any); ok {
		for name := range props {
			if !propName.MatchString(name) {
				return fmt.Errorf("property name %q outside 1-64 characters of [A-Za-z0-9_.-]", name)
			}
		}
	}
	return nil
}

// ErrHighRiskUnconfined refuses a high-risk server under an unconfined
// launcher (standalone profile).
var ErrHighRiskUnconfined = errors.New("high-risk server classes need the enforced profile")

// Start launches every configured server and indexes its tools. A server
// whose tool set cannot be presented (two tools mapping to one public name,
// FR-1.49; an over-long public name, CP-42; an invalid definition, FR-5.22)
// is not enabled: its instance is shut down, the reason is kept for
// Disabled, and the other servers run. A server that cannot be launched at
// all still fails startup.
func Start(ctx context.Context, servers []config.Server, opts Options) (*Registry, error) {
	if opts.Capabilities == nil {
		return nil, errors.New("backend: a capability checker is required (FR-4.13)")
	}
	if opts.Launcher == nil {
		opts.Launcher = pipeline.SubprocessLauncher{StderrBytes: opts.Limits.StderrBytes}
	}
	if opts.Manifests == nil {
		opts.Manifests = pipeline.LiveManifest{}
	}
	if opts.Secrets == nil {
		opts.Secrets = pipeline.NoSecrets{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Limits.PerPrincipal <= 0 || opts.Limits.Total <= 0 {
		return nil, errors.New("backend: concurrency limits must be positive")
	}
	r := &Registry{limits: opts.Limits, launcher: opts.Launcher, caps: opts.Capabilities, log: opts.Log, opts: opts,
		servers: map[string]*Server{}, tools: map[string]*ToolRef{}, disabled: map[string]string{}, perPrinc: map[string]*fifo{}, total: newFIFO(opts.Limits.Total)}
	r.watcher, _ = opts.Manifests.(pipeline.ManifestWatcher)
	for _, sc := range servers {
		s, err := r.launch(ctx, sc)
		if errors.Is(err, pipeline.ErrServerSuspended) {
			// A suspended revision (drift, changed artifact) keeps the rest
			// of the catalog running; the source recorded the evidence.
			r.log.Error("server not started: revision suspended", "alias", sc.Alias, "err", err)
			continue
		}
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("server %q: %w", sc.Alias, err)
		}
		if err := r.index(s); err != nil {
			// FR-1.49: the revision is not enabled; the rest of the
			// catalog runs.
			r.log.Error("server not enabled: tool set cannot be presented", "alias", sc.Alias, "revision", s.Revision, "err", err)
			s.peek().close()
			r.smu.Lock()
			r.disabled[sc.Alias] = err.Error()
			r.smu.Unlock()
		}
	}
	return r, nil
}

// Disabled returns, by alias, the servers that were launched but not
// enabled because their tool set cannot be presented, with the reason
// (FR-1.49: it names both backend tool names of a collision).
func (r *Registry) Disabled() map[string]string {
	r.smu.RLock()
	defer r.smu.RUnlock()
	out := make(map[string]string, len(r.disabled))
	for k, v := range r.disabled {
		out[k] = v
	}
	return out
}

// index adds a launched server and its tools to the public-name index. It
// checks every tool first and changes the index only when all pass.
func (r *Registry) index(s *Server) error {
	seen := map[string]string{} // public -> backend name
	refs := make([]*ToolRef, 0, len(s.Tools))
	for _, t := range s.Tools {
		if err := CheckToolDefinition(t); err != nil {
			return fmt.Errorf("server %q tool %q: drift: %w", s.Alias, t.Name, err)
		}
		pub := PublicName(s.Alias, t.Name)
		if len(pub) > 64 {
			return fmt.Errorf("server %q tool %q: public name %q exceeds 64 characters (CP-42)", s.Alias, t.Name, pub)
		}
		if prev, dup := seen[pub]; dup {
			return fmt.Errorf("server %q: tools %q and %q both map to public name %q (FR-1.49)", s.Alias, prev, t.Name, pub)
		}
		seen[pub] = t.Name
		refs = append(refs, &ToolRef{Public: pub, Server: s, Tool: t, Revision: s.Revision + "/" + t.Name})
	}
	r.smu.Lock()
	defer r.smu.Unlock()
	r.servers[s.Alias] = s
	for _, ref := range refs {
		r.tools[ref.Public] = ref
		r.public = append(r.public, ref.Public)
	}
	sort.Strings(r.public)
	return nil
}

// envelopeBytes is the allowance for the JSON-RPC envelope and content
// framing around a result of CP-08 bytes.
const envelopeBytes = 64 << 10

func (r *Registry) launch(ctx context.Context, sc config.Server) (*Server, error) {
	spec := pipeline.ServerSpec{Alias: sc.Alias, Command: sc.Command, Args: sc.Args, Dir: sc.Dir, RiskClasses: sc.RiskClasses, HighRisk: sc.HighRisk()}
	if spec.HighRisk && !r.opts.Launcher.Confined() {
		return nil, fmt.Errorf("%w (risk classes %v, launcher %s)", ErrHighRiskUnconfined, sc.RiskClasses, r.opts.Launcher.Name())
	}
	if err := pipeline.CheckLaunchSpec(spec); err != nil {
		return nil, err
	}
	s := &Server{Alias: sc.Alias, cfg: sc, spec: spec}
	inst, ts, era, err := r.start(ctx, s)
	if err != nil {
		return nil, err
	}
	s.Tools, s.Revision, s.Verified, s.ManifestSource, s.Era = ts.Tools, ts.Revision, ts.Verified, ts.Source, era
	s.cur = inst
	inst.started.Store(true)
	if !ts.Verified {
		r.log.Warn("server tool definitions are unverified (live list; no signed manifest)", "alias", sc.Alias, "revision", ts.Revision)
	}
	return s, nil
}

// start launches one instance of s: secrets, launcher, MCP handshake and
// the tool set from the ManifestSource.
func (r *Registry) start(ctx context.Context, s *Server) (*instance, pipeline.ToolSet, string, error) {
	sc, spec := s.cfg, s.spec
	secrets, err := r.opts.Secrets.Resolve(ctx, pipeline.SecretRequest{Server: sc.Alias, Refs: sc.SecretEnv})
	if err != nil {
		return nil, pipeline.ToolSet{}, "", fmt.Errorf("secrets: %w", err)
	}
	// SR-2.14-1: the instance environment is built from an allowlist, never
	// inherited wholesale.
	if spec.Env, err = pipeline.MergeEnv(pipeline.BaseEnv(), sc.Env, secrets); err != nil {
		return nil, pipeline.ToolSet{}, "", err
	}
	if d, ok := r.opts.Secrets.(interface{ InstanceDir(alias string) string }); ok {
		spec.SecretDir = d.InstanceDir(sc.Alias)
	}
	proc, err := r.opts.Launcher.Launch(ctx, spec)
	if err != nil {
		return nil, pipeline.ToolSet{}, "", fmt.Errorf("launch: %w", err)
	}
	limit := int(r.opts.Limits.ResultBytes) + envelopeBytes
	w := &lineWriter{p: proc}
	ff := newFrameFilter(proc, limit)
	// FR-5.20: a server-initiated request other than ping is answered
	// with -32601 here and never reaches the SDK client, which would
	// otherwise answer roots/list itself.
	ff.reply = w.Write
	ff.refused = func(method string) {
		r.log.Warn("server-initiated request refused (FR-5.20)", "alias", sc.Alias, "method", method)
	}
	ff.progress = r.routeProgress
	transport := &mcp.IOTransport{Reader: ff, Writer: w, MaxLineLength: limit + 1024}
	inst := &instance{proc: proc, filter: ff}
	copts := &mcp.ClientOptions{
		// SR-5.6-2: no sampling, elicitation or roots capability
		// southbound (the SDK declares roots unless told otherwise).
		Capabilities: &mcp.ClientCapabilities{},
	}
	if r.watcher != nil {
		copts.ToolListChangedHandler = func(context.Context, *mcp.ToolListChangedRequest) {
			if inst.started.Load() {
				go r.listChanged(s, inst) //nolint:gosec // the notification context ends with the handler; the re-check has its own timeout
			}
		}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "secure-mcp-gateway", Version: Version}, copts)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// FR-5.19: release 1.0 speaks the 2025-11-25 era southbound, so the
	// handshake is initialize with that version (the SDK would otherwise
	// try the 2026-07-28 server/discover first; that probe is deferred,
	// SRS Appendix N).
	sess, err := client.Connect(cctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: LegacyEra})
	if err != nil {
		proc.Close()
		return nil, pipeline.ToolSet{}, "", fmt.Errorf("connect %s: %w (stderr: %s)", sc.Command, err, stderrForError(proc.Stderr(), secrets))
	}
	inst.session = sess
	era := ""
	if ir := sess.InitializeResult(); ir != nil && ir.ProtocolVersion != "" {
		era = ir.ProtocolVersion
	}
	// FR-5.40: a verified ManifestSource compares the negotiated era with
	// the manifest's.
	spec.NegotiatedEra = era
	// FR-5.21: the complete live tool list across all pages.
	inst.live = func(ctx context.Context) ([]*mcp.Tool, error) {
		var tools []*mcp.Tool
		for t, err := range sess.Tools(ctx, nil) {
			if err != nil {
				return nil, fmt.Errorf("tools/list: %w", err)
			}
			tools = append(tools, t)
		}
		return tools, nil
	}
	ts, err := r.opts.Manifests.Tools(cctx, spec, inst.live)
	if err != nil {
		sess.Close()
		return nil, pipeline.ToolSet{}, "", err
	}
	return inst, ts, era, nil
}

// stderrTailBytes bounds the server output quoted in a start error.
const stderrTailBytes = 2 << 10

// stderrForError is the end of a server's diagnostic output for a start
// error: at most stderrTailBytes, with every secret value delivered to the
// instance replaced. The error reaches the diagnostic log and the
// service manager's log, and a server can print its own environment.
func stderrForError(stderr string, secrets map[string]string) string {
	// Redact before cutting, so that a cut cannot leave part of a value.
	for _, v := range secrets {
		if len(v) >= 4 {
			stderr = strings.ReplaceAll(stderr, v, "[REDACTED]")
		}
	}
	if len(stderr) > stderrTailBytes {
		stderr = "[...]" + strings.ToValidUTF8(stderr[len(stderr)-stderrTailBytes:], "")
	}
	return stderr
}

// restart replaces a server's instance after an upstream timeout or a
// failed instance (Appendix L HF-17, HF-19). It does nothing when the
// instance was already replaced. Calls wait for the new instance; the old
// one is shut down first, so that its teardown (secret deliveries, sandbox)
// cannot affect the new one. A relaunch that fails, or whose revision
// differs from the enabled one, suspends the server.
func (r *Registry) restart(s *Server, old *instance, reason string) {
	s.mu.Lock()
	if s.cur != old || s.suspended.Load() {
		s.mu.Unlock()
		return
	}
	if s.ready != nil {
		select {
		case <-s.ready:
		default:
			s.mu.Unlock()
			return // a restart is already under way
		}
	}
	ready := make(chan struct{})
	s.ready = ready
	s.mu.Unlock()
	r.inFlight.Add(1)
	go func() {
		defer r.inFlight.Done()
		old.close()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		inst, ts, _, err := r.start(ctx, s)
		switch {
		case err != nil:
			err = fmt.Errorf("restart after %s failed: %w", reason, err)
		case ts.Revision != s.Revision:
			inst.close()
			inst, err = nil, fmt.Errorf("restart after %s: revision %s differs from the enabled revision %s", reason, ts.Revision, s.Revision)
		}
		s.mu.Lock()
		if inst != nil {
			if s.suspended.Load() {
				inst.close()
			} else {
				s.cur = inst
				inst.started.Store(true)
				s.restarts.Add(1)
			}
		}
		close(ready)
		s.mu.Unlock()
		if err != nil {
			r.log.Error("server instance not restarted", "alias", s.Alias, "err", err)
			r.Suspend(s.Alias, err.Error())
			return
		}
		r.log.Warn("server instance restarted", "alias", s.Alias, "reason", reason)
	}()
}

// routeProgress hands a backend progress notification to the call that
// owns its token; others are dropped. The frame filter calls it in line
// order, so every notification the server wrote before its response is
// handled before the response reaches the waiting call.
func (r *Registry) routeProgress(p *mcp.ProgressNotificationParams) {
	if p == nil {
		return
	}
	if f, ok := r.progress.Load(fmt.Sprint(p.ProgressToken)); ok {
		f.(func(*mcp.ProgressNotificationParams))(p)
	}
}

// lineWriter serializes writes to the instance's stdin: the SDK writes each
// message with one Write, and the frame filter writes its refusals.
type lineWriter struct {
	mu sync.Mutex
	p  pipeline.Process
}

func (w *lineWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.p.Write(b)
}

// Close runs the process's shutdown sequence.
func (w *lineWriter) Close() error { return w.p.Close() }

// Version is the Gateway release version string presented as clientInfo
// and serverInfo. Set by the build.
var Version = "0.0.0-dev"

// LegacyEra is the protocol version of the southbound handshake (FR-5.19).
const LegacyEra = "2025-11-25"

// Resolve maps a public name to its backend tool.
func (r *Registry) Resolve(public string) *ToolRef {
	r.smu.RLock()
	defer r.smu.RUnlock()
	return r.tools[public]
}

// PublicNames returns every public name in ascending order (FR-1.25).
func (r *Registry) PublicNames() []string {
	r.smu.RLock()
	defer r.smu.RUnlock()
	return append([]string(nil), r.public...)
}

// Servers returns the launched, not suspended servers by alias.
func (r *Registry) Servers() map[string]*Server {
	r.smu.RLock()
	defer r.smu.RUnlock()
	out := make(map[string]*Server, len(r.servers))
	for k, v := range r.servers {
		out[k] = v
	}
	return out
}

// ErrSuspended refuses a call to a suspended server.
var ErrSuspended = errors.New("server suspended")

// Suspend removes a server's tools from the index and tears its instance
// down (SR-3.8-1, SR-3-3). Calls already holding a ToolRef are refused with
// ErrSuspended. It reports false when no running server has the alias.
func (r *Registry) Suspend(alias, reason string) bool {
	r.smu.Lock()
	s := r.servers[alias]
	if s == nil {
		r.smu.Unlock()
		return false
	}
	s.suspended.Store(true)
	delete(r.servers, alias)
	kept := r.public[:0]
	for _, pub := range r.public {
		if ref := r.tools[pub]; ref != nil && ref.Server == s {
			delete(r.tools, pub)
			continue
		}
		kept = append(kept, pub)
	}
	r.public = kept
	r.smu.Unlock()
	r.log.Error("server suspended and torn down", "alias", alias, "reason", reason)
	s.peek().close()
	return true
}

// listChanged re-checks a server's tool list against its manifest after a
// notifications/tools/list_changed and suspends it on drift.
func (r *Registry) listChanged(s *Server, inst *instance) {
	if s.suspended.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := r.watcher.ListChanged(ctx, s.spec, inst.live)
	switch {
	case errors.Is(err, pipeline.ErrServerSuspended):
		r.Suspend(s.Alias, err.Error())
	case err != nil:
		r.log.Warn("tool list re-check failed", "alias", s.Alias, "err", err)
	}
}

// Launcher returns the launcher in use.
func (r *Registry) Launcher() pipeline.Launcher { return r.launcher }

// Errors from Call.
var (
	ErrQueueFull = errors.New("dispatch queue full")  // -31005
	ErrTimeout   = errors.New("upstream timeout")     // -31009 UPSTREAM_TIMEOUT; the instance is replaced
	ErrTooLarge  = errors.New("result exceeds bound") // -31003 withhold
	// ErrInputRequired: the backend returned an InputRequiredResult and the
	// MRTR Relay Profile is not available (FR-5.24, -31010).
	ErrInputRequired = errors.New("backend requested client input")
	// ErrInvalidOutput: the instance wrote a line that is not a single-line
	// UTF-8 JSON-RPC message; the in-flight calls fail and the instance is
	// replaced (FR-5.13, FR-5.14; -31007).
	ErrInvalidOutput = errors.New("instance wrote an invalid stdout line")
	// ErrInvalidResult: the response failed result validation, for example
	// an unrecognized resultType or a malformed CallToolResult (FR-5.23,
	// SR-5.20-1; -31003, withheld).
	ErrInvalidResult = errors.New("backend result is invalid")
	// ErrInstanceFailed: the instance ended after the call was dispatched,
	// so the outcome is unknown; the call is not retried (SR-7.2-1).
	ErrInstanceFailed = errors.New("instance failed after dispatch")
)

// CapabilityError wraps a refused launch capability.
type CapabilityError struct{ Err error }

func (e *CapabilityError) Error() string { return "dispatch refused: " + e.Err.Error() }
func (e *CapabilityError) Unwrap() error { return e.Err }

// BackendError carries a backend JSON-RPC error code without its message
// (FR-1.32).
type BackendError struct{ Code int64 }

func (e *BackendError) Error() string { return fmt.Sprintf("backend error %d", e.Code) }

// Dispatch is one call handed to the dispatcher.
type Dispatch struct {
	Principal  string
	Ref        *ToolRef
	Arguments  json.RawMessage
	Capability string
	Binding    pipeline.Binding
	// Progress, when set, receives the backend's progress notifications
	// for this call (FR-1.39). The backend sees a Gateway-issued token,
	// never the northbound one; Progress is not called after Call returns.
	Progress func(*mcp.ProgressNotificationParams)
}

// Call dispatches one tool call. It first spends the launch capability
// (refusing without one), then waits for a slot under the concurrency
// bounds, and returns the complete, size-checked result.
func (r *Registry) Call(ctx context.Context, d Dispatch) (*mcp.CallToolResult, error) {
	if d.Ref == nil {
		return nil, errors.New("dispatch without a tool")
	}
	if d.Ref.Server != nil && d.Ref.Server.suspended.Load() {
		return nil, ErrSuspended
	}
	if d.Binding.PublicName != d.Ref.Public {
		return nil, &CapabilityError{pipeline.ErrCapabilityMismatch}
	}
	if err := r.caps.Consume(d.Capability, d.Binding); err != nil {
		return nil, &CapabilityError{err}
	}
	release, err := r.acquire(ctx, d.Principal)
	if err != nil {
		return nil, err
	}
	defer release()
	r.inFlight.Add(1)
	defer r.inFlight.Done()

	cctx, cancel := context.WithTimeout(ctx, r.limits.UpstreamTimeout)
	defer cancel()
	var a any
	if len(d.Arguments) > 0 {
		if err := json.Unmarshal(d.Arguments, &a); err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "arguments must be a JSON object"}
		}
	}
	params := &mcp.CallToolParams{Name: d.Ref.Tool.Name, Arguments: a}
	if d.Progress != nil {
		tok := fmt.Sprintf("smcp-%d", r.progSeq.Add(1))
		var pmu sync.Mutex
		done := false
		r.progress.Store(tok, func(p *mcp.ProgressNotificationParams) {
			pmu.Lock()
			defer pmu.Unlock()
			if !done {
				d.Progress(p)
			}
		})
		defer func() {
			r.progress.Delete(tok)
			pmu.Lock()
			done = true
			pmu.Unlock()
		}()
		params.Meta = mcp.Meta{"progressToken": tok}
	}
	s := d.Ref.Server
	inst, err := s.current(cctx)
	if err != nil {
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, ErrTimeout
		}
		return nil, err
	}
	if inst == nil || s.suspended.Load() {
		return nil, ErrSuspended
	}
	res, err := inst.session.CallTool(cctx, params)
	if err != nil {
		var we *jsonrpc.Error
		if errors.As(err, &we) {
			switch {
			case we.Code == tooLargeCode && we.Message == tooLargeMessage:
				return nil, ErrTooLarge
			case we.Code == tooLargeCode && we.Message == inputRequiredMessage:
				return nil, ErrInputRequired
			case we.Code == tooLargeCode && we.Message == invalidResultMessage:
				return nil, ErrInvalidResult
			}
			return nil, &BackendError{Code: we.Code}
		}
		if inst.filter.invalid.Load() {
			// FR-5.14: an invalid stdout line ends the connection; the
			// instance is terminated and replaced.
			r.restart(s, inst, "invalid stdout line")
			return nil, ErrInvalidOutput
		}
		if cctx.Err() != nil && ctx.Err() == nil {
			// The instance may still be working on the call, or be stuck
			// mid-message: replace it (HF-17, HF-19).
			r.restart(s, inst, "upstream timeout")
			return nil, ErrTimeout
		}
		if ctx.Err() != nil {
			// Northbound cancellation or the client deadline: the SDK has
			// sent notifications/cancelled for the request (FR-5.26).
			return nil, err
		}
		if !instanceGone(err) && isDecodeError(err) {
			// The response arrived but is not a CallToolResult the SDK can
			// decode (SR-5.20-1); the instance keeps serving.
			r.log.Warn("backend result rejected", "alias", s.Alias, "err", err)
			return nil, ErrInvalidResult
		}
		// The connection ended (exit, EOF, closed pipe) after the call was
		// sent: replace the instance; the call is not retried (SR-7.2-1).
		r.restart(s, inst, "instance failed")
		return nil, fmt.Errorf("%w: %w", ErrInstanceFailed, err)
	}
	// FR-4.10: the response was bounded while read; check the decoded size
	// before inspection as well.
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > r.limits.ResultBytes {
		return nil, ErrTooLarge
	}
	return res, nil
}

// instanceGone reports whether a call error means the instance's transport
// is gone. The SDK wraps a read that finds the connection closed in
// mcp.ErrConnectionClosed, but a write to a pipe the exited process closed
// can surface as a bare io.ErrClosedPipe; both mean the next call needs a
// new instance.
func instanceGone(err error) bool {
	return errors.Is(err, mcp.ErrConnectionClosed) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// isDecodeError reports whether a CallTool error is the SDK failing to
// decode the response as a CallToolResult.
func isDecodeError(err error) bool {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	return errors.As(err, &se) || errors.As(err, &te) || strings.Contains(err.Error(), "json: ")
}

// acquire takes a per-principal slot and a total slot, waiting in FIFO
// order when either is busy. The queue bound counts calls waiting for
// either slot and is checked and incremented atomically.
func (r *Registry) acquire(ctx context.Context, principal string) (func(), error) {
	r.mu.Lock()
	pc := r.perPrinc[principal]
	if pc == nil {
		pc = newFIFO(r.limits.PerPrincipal)
		r.perPrinc[principal] = pc
	}
	gotP := pc.tryAcquire()
	gotT := gotP && r.total.tryAcquire()
	if gotP && gotT {
		r.mu.Unlock()
		return func() { r.total.release(); pc.release() }, nil
	}
	if r.waiting >= r.limits.Queue {
		if gotP {
			pc.release()
		}
		r.mu.Unlock()
		return nil, ErrQueueFull
	}
	r.waiting++
	r.mu.Unlock()
	done := func() { r.mu.Lock(); r.waiting--; r.mu.Unlock() }
	if !gotP {
		if err := pc.acquire(ctx); err != nil {
			done()
			return nil, err
		}
	}
	if err := r.total.acquire(ctx); err != nil {
		pc.release()
		done()
		return nil, err
	}
	done()
	return func() { r.total.release(); pc.release() }, nil
}

// Waiting returns the number of queued calls (tests and health).
func (r *Registry) Waiting() int { r.mu.Lock(); defer r.mu.Unlock(); return r.waiting }

// Stderr returns the bounded diagnostic buffer of a server (FR-5.15).
func (s *Server) Stderr() string {
	if in := s.peek(); in != nil && in.proc != nil {
		return in.proc.Stderr()
	}
	return ""
}

// OversizedFrames returns how many oversized messages the server sent (0
// for a Server value that was not launched, such as a test fixture).
func (s *Server) OversizedFrames() uint64 {
	if in := s.peek(); in != nil && in.filter != nil {
		return in.filter.oversized.Load()
	}
	return 0
}

// RefusedRequests returns how many server-initiated requests the current
// instance sent that the Gateway refused with -32601 (FR-5.20).
func (s *Server) RefusedRequests() uint64 {
	if in := s.peek(); in != nil && in.filter != nil {
		return in.filter.refusedN.Load()
	}
	return 0
}

// Close shuts every instance down after in-flight calls finish (FR-5.27
// ordering is the Process's shutdown sequence).
func (r *Registry) Close() {
	r.inFlight.Wait()
	r.smu.RLock()
	defer r.smu.RUnlock()
	for _, s := range r.servers {
		s.peek().close()
	}
}

// fifo is a counting semaphore that grants waiters in arrival order.
type fifo struct {
	mu      sync.Mutex
	cap     int
	used    int
	waiters list.List // of chan struct{}
}

func newFIFO(n int) *fifo { return &fifo{cap: n} }

// tryAcquire takes a slot only when one is free and nobody is waiting, so
// a newcomer never overtakes the queue.
func (f *fifo) tryAcquire() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used < f.cap && f.waiters.Len() == 0 {
		f.used++
		return true
	}
	return false
}

func (f *fifo) acquire(ctx context.Context) error {
	f.mu.Lock()
	if f.used < f.cap && f.waiters.Len() == 0 {
		f.used++
		f.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	el := f.waiters.PushBack(ch)
	f.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		f.mu.Lock()
		select {
		case <-ch:
			// Granted while cancelling: hand the slot on.
			f.mu.Unlock()
			f.release()
		default:
			f.waiters.Remove(el)
			f.mu.Unlock()
		}
		return ctx.Err()
	}
}

// release frees a slot, transferring it directly to the oldest waiter.
func (f *fifo) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if el := f.waiters.Front(); el != nil {
		f.waiters.Remove(el)
		close(el.Value.(chan struct{}))
		return
	}
	f.used--
}

// tooLargeCode and tooLargeMessage mark the error the frame filter
// substitutes for an oversized response.
const (
	tooLargeCode         = jsonrpc.CodeInternalError
	tooLargeMessage      = "local.smcpgw/result-too-large"
	inputRequiredMessage = "local.smcpgw/input-required"
	invalidResultMessage = "local.smcpgw/invalid-result"
)

// frameFilter reads newline-delimited JSON-RPC from the server and bounds
// each line to limit bytes while reading. An oversized line is discarded;
// when its request ID can be read from the retained prefix, an error
// response for that ID takes its place.
//
// It also screens the server's messages before the SDK client sees them:
// a request other than ping is answered with -32601 through reply and
// dropped (FR-5.20, SR-5.6-2), a response carrying an InputRequiredResult
// is replaced by an error the dispatcher maps to ErrInputRequired
// (FR-5.24), and notifications/progress go to progress (FR-1.39) instead
// of the SDK client, whose notification handlers can run after the
// response that followed them.
type frameFilter struct {
	r         *bufio.Reader
	limit     int
	pending   []byte
	oversized atomic.Uint64
	refusedN  atomic.Uint64
	// invalid is set when the server wrote a line that is not a
	// single-line UTF-8 JSON-RPC message (FR-5.13, FR-5.14). The line is
	// replaced by an error, which ends the connection.
	invalid  atomic.Bool
	reply    func([]byte) (int, error)
	refused  func(method string)
	progress func(*mcp.ProgressNotificationParams)
}

func newFrameFilter(r io.Reader, limit int) *frameFilter {
	return &frameFilter{r: bufio.NewReaderSize(r, 64<<10), limit: limit}
}

func (f *frameFilter) Close() error { return nil }

func (f *frameFilter) Read(p []byte) (int, error) {
	for len(f.pending) == 0 {
		line, err := f.next()
		if len(line) > 0 {
			f.pending = line
			break
		}
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

// next returns the next line (with its newline), a substitute for an
// oversized line, or nothing when an oversized line had no readable ID.
func (f *frameFilter) next() ([]byte, error) {
	var buf []byte
	over := false
	for {
		chunk, err := f.r.ReadSlice('\n')
		if !over {
			if len(buf)+len(chunk) > f.limit {
				room := f.limit - len(buf)
				buf = append(buf, chunk[:room]...)
				over = true
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case err == nil:
			if !over {
				out := f.screen(buf)
				if f.invalid.Load() {
					// FR-5.14: end the connection; the dispatcher fails the
					// in-flight calls and replaces the instance.
					return nil, errInvalidLine
				}
				return out, nil
			}
			return f.substitute(buf), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			if over {
				return f.substitute(buf), err
			}
			return f.screen(buf), err
		}
	}
}

// screen applies the server-initiated request, progress, InputRequiredResult
// and resultType rules (FR-5.20, FR-5.24, FR-5.23) to one complete line,
// after checking that it holds UTF-8 JSON-RPC 2.0 (FR-5.13, FR-5.14). A
// JSON-RPC batch line is split and each member screened as its own message;
// the members that survive are passed on one per line, so no request inside
// a batch reaches the SDK client unscreened. A line that is not JSON-RPC
// sets invalid, which ends the connection.
func (f *frameFilter) screen(line []byte) []byte {
	body := bytes.TrimRight(line, "\r\n")
	if len(bytes.TrimSpace(body)) == 0 {
		return nil // an empty line carries no message
	}
	if t := bytes.TrimLeft(body, " \t"); t[0] == '[' {
		var members []json.RawMessage
		if !utf8.Valid(body) || json.Unmarshal(body, &members) != nil || len(members) == 0 {
			f.invalid.Store(true)
			return nil
		}
		var out []byte
		for _, m := range members {
			var c bytes.Buffer
			if json.Compact(&c, m) != nil {
				f.invalid.Store(true)
				return nil
			}
			c.WriteByte('\n')
			out = append(out, f.screenOne(c.Bytes())...)
		}
		return out
	}
	return f.screenOne(line)
}

// screenOne screens a line holding one JSON-RPC message.
func (f *frameFilter) screenOne(line []byte) []byte {
	body := bytes.TrimRight(line, "\r\n")
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  *string         `json:"method"`
		Params  json.RawMessage `json:"params"`
		Result  json.RawMessage `json:"result"`
	}
	// FR-5.13, FR-5.14: every line is one UTF-8 JSON-RPC 2.0 message.
	if !utf8.Valid(body) || json.Unmarshal(body, &m) != nil || m.JSONRPC != "2.0" {
		f.invalid.Store(true)
		return nil
	}
	hasID := len(m.ID) > 0 && string(m.ID) != "null"
	switch {
	case m.Method != nil && hasID && *m.Method != "ping":
		f.refusedN.Add(1)
		if f.refused != nil {
			f.refused(*m.Method)
		}
		if f.reply != nil {
			msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"method not found"}}`+"\n", m.ID, jsonrpc.CodeMethodNotFound)
			_, _ = f.reply([]byte(msg))
		}
		return nil
	case m.Method != nil && !hasID && *m.Method == "notifications/progress" && f.progress != nil:
		var p mcp.ProgressNotificationParams
		if json.Unmarshal(m.Params, &p) == nil {
			f.progress(&p)
		}
		return nil
	case m.Method == nil && hasID && len(m.Result) > 0:
		var res struct {
			ResultType *string `json:"resultType"`
		}
		if json.Unmarshal(m.Result, &res) != nil {
			// Not an object: the SDK rejects it as a result (SR-5.20-1).
			return line
		}
		switch {
		case res.ResultType == nil || *res.ResultType == "complete":
			// FR-5.23: no resultType is "complete".
		case *res.ResultType == "input_required":
			return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`+"\n", m.ID, tooLargeCode, inputRequiredMessage))
		default:
			// FR-5.23: an unrecognized resultType is an invalid result.
			return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`+"\n", m.ID, tooLargeCode, invalidResultMessage))
		}
	}
	return line
}

// errInvalidLine ends the instance's connection after an invalid line.
var errInvalidLine = errors.New("instance wrote a line that is not a single-line UTF-8 JSON-RPC message")

func (f *frameFilter) substitute(prefix []byte) []byte {
	f.oversized.Add(1)
	id := requestID(prefix)
	if id == nil {
		return nil
	}
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`+"\n", id, tooLargeCode, tooLargeMessage)
	return []byte(msg)
}

// requestID reads the top-level "id" member from the start of a JSON
// object, skipping members before it; it gives up at the first value it
// cannot read whole.
func requestID(prefix []byte) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(prefix))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil
		}
		if k == "id" {
			return v
		}
	}
	return nil
}
