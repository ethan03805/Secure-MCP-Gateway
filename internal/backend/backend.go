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
	"sync"
	"sync/atomic"
	"time"

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
	session        *mcp.ClientSession
	proc           pipeline.Process
	filter         *frameFilter
}

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
	servers  map[string]*Server
	tools    map[string]*ToolRef
	public   []string

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

// Start launches every configured server and indexes its tools. Any server
// whose tool set cannot be presented (collision, over-long name, invalid
// definition) fails startup with the reason; the Gateway does not run with a
// partially enabled catalog in this slice.
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
	r := &Registry{limits: opts.Limits, launcher: opts.Launcher, caps: opts.Capabilities, log: opts.Log,
		servers: map[string]*Server{}, tools: map[string]*ToolRef{}, perPrinc: map[string]*fifo{}, total: newFIFO(opts.Limits.Total)}
	for _, sc := range servers {
		s, err := r.launch(ctx, sc, opts)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("server %q: %w", sc.Alias, err)
		}
		r.servers[s.Alias] = s
		seen := map[string]string{} // public -> backend name
		for _, t := range s.Tools {
			if err := CheckToolDefinition(t); err != nil {
				r.Close()
				return nil, fmt.Errorf("server %q tool %q: drift: %w", sc.Alias, t.Name, err)
			}
			pub := PublicName(s.Alias, t.Name)
			if len(pub) > 64 {
				r.Close()
				return nil, fmt.Errorf("server %q tool %q: public name %q exceeds 64 characters (CP-42)", sc.Alias, t.Name, pub)
			}
			if prev, dup := seen[pub]; dup {
				r.Close()
				return nil, fmt.Errorf("server %q: tools %q and %q both map to public name %q (FR-1.49)", sc.Alias, prev, t.Name, pub)
			}
			seen[pub] = t.Name
			r.tools[pub] = &ToolRef{Public: pub, Server: s, Tool: t, Revision: s.Revision + "/" + t.Name}
			r.public = append(r.public, pub)
		}
	}
	sort.Strings(r.public)
	return r, nil
}

// envelopeBytes is the allowance for the JSON-RPC envelope and content
// framing around a result of CP-08 bytes.
const envelopeBytes = 64 << 10

func (r *Registry) launch(ctx context.Context, sc config.Server, opts Options) (*Server, error) {
	spec := pipeline.ServerSpec{Alias: sc.Alias, Command: sc.Command, Args: sc.Args, Dir: sc.Dir, RiskClasses: sc.RiskClasses, HighRisk: sc.HighRisk()}
	if spec.HighRisk && !opts.Launcher.Confined() {
		return nil, fmt.Errorf("%w (risk classes %v, launcher %s)", ErrHighRiskUnconfined, sc.RiskClasses, opts.Launcher.Name())
	}
	if err := pipeline.CheckLaunchSpec(spec); err != nil {
		return nil, err
	}
	secrets, err := opts.Secrets.Resolve(ctx, pipeline.SecretRequest{Server: sc.Alias, Refs: sc.SecretEnv})
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	// SR-2.14-1: the instance environment is built from an allowlist, never
	// inherited wholesale.
	if spec.Env, err = pipeline.MergeEnv(pipeline.BaseEnv(), sc.Env, secrets); err != nil {
		return nil, err
	}
	proc, err := opts.Launcher.Launch(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("launch: %w", err)
	}
	limit := int(opts.Limits.ResultBytes) + envelopeBytes
	ff := newFrameFilter(proc, limit)
	transport := &mcp.IOTransport{Reader: ff, Writer: procCloser{proc}, MaxLineLength: limit + 1024}
	client := mcp.NewClient(&mcp.Implementation{Name: "secure-mcp-gateway", Version: Version}, nil)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sess, err := client.Connect(cctx, transport, nil)
	if err != nil {
		proc.Close()
		return nil, fmt.Errorf("connect %s: %w (stderr: %s)", sc.Command, err, proc.Stderr())
	}
	s := &Server{Alias: sc.Alias, cfg: sc, session: sess, proc: proc, filter: ff}
	if ir := sess.InitializeResult(); ir != nil && ir.ProtocolVersion != "" {
		s.Era = ir.ProtocolVersion
	}
	// FR-5.21: the complete live tool list across all pages.
	live := func(ctx context.Context) ([]*mcp.Tool, error) {
		var tools []*mcp.Tool
		for t, err := range sess.Tools(ctx, nil) {
			if err != nil {
				return nil, fmt.Errorf("tools/list: %w", err)
			}
			tools = append(tools, t)
		}
		return tools, nil
	}
	ts, err := opts.Manifests.Tools(cctx, spec, live)
	if err != nil {
		sess.Close()
		return nil, err
	}
	s.Tools, s.Revision, s.Verified, s.ManifestSource = ts.Tools, ts.Revision, ts.Verified, ts.Source
	if !ts.Verified {
		r.log.Warn("server tool definitions are unverified (live list; no signed manifest)", "alias", sc.Alias, "revision", ts.Revision)
	}
	return s, nil
}

// procCloser makes the process the transport's writer; closing it runs the
// shutdown sequence.
type procCloser struct{ p pipeline.Process }

func (w procCloser) Write(b []byte) (int, error) { return w.p.Write(b) }
func (w procCloser) Close() error                { return w.p.Close() }

// Version is the Gateway release version string presented as clientInfo
// and serverInfo. Set by the build.
var Version = "0.0.0-dev"

// Resolve maps a public name to its backend tool.
func (r *Registry) Resolve(public string) *ToolRef { return r.tools[public] }

// PublicNames returns every public name in ascending order (FR-1.25).
func (r *Registry) PublicNames() []string { return append([]string(nil), r.public...) }

// Servers returns the launched servers by alias.
func (r *Registry) Servers() map[string]*Server { return r.servers }

// Launcher returns the launcher in use.
func (r *Registry) Launcher() pipeline.Launcher { return r.launcher }

// Errors from Call.
var (
	ErrQueueFull = errors.New("dispatch queue full")  // -31005
	ErrTimeout   = errors.New("upstream timeout")     // -31008 / indeterminate
	ErrTooLarge  = errors.New("result exceeds bound") // -31003 withhold
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
	Principal     string
	Ref           *ToolRef
	Arguments     json.RawMessage
	ProgressToken any
	Capability    string
	Binding       pipeline.Binding
}

// Call dispatches one tool call. It first spends the launch capability
// (refusing without one), then waits for a slot under the concurrency
// bounds, and returns the complete, size-checked result.
func (r *Registry) Call(ctx context.Context, d Dispatch) (*mcp.CallToolResult, error) {
	if d.Ref == nil {
		return nil, errors.New("dispatch without a tool")
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
	if d.ProgressToken != nil {
		params.Meta = mcp.Meta{"progressToken": d.ProgressToken}
	}
	res, err := d.Ref.Server.session.CallTool(cctx, params)
	if err != nil {
		var we *jsonrpc.Error
		if errors.As(err, &we) {
			if we.Code == tooLargeCode && we.Message == tooLargeMessage {
				return nil, ErrTooLarge
			}
			return nil, &BackendError{Code: we.Code}
		}
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, ErrTimeout
		}
		return nil, err
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
func (s *Server) Stderr() string { return s.proc.Stderr() }

// OversizedFrames returns how many oversized messages the server sent.
func (s *Server) OversizedFrames() uint64 { return s.filter.oversized.Load() }

// Close shuts every instance down after in-flight calls finish (FR-5.27
// ordering is the Process's shutdown sequence).
func (r *Registry) Close() {
	r.inFlight.Wait()
	for _, s := range r.servers {
		if s.session != nil {
			_ = s.session.Close()
		}
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
	tooLargeCode    = jsonrpc.CodeInternalError
	tooLargeMessage = "local.smcpgw/result-too-large"
)

// frameFilter reads newline-delimited JSON-RPC from the server and bounds
// each line to limit bytes while reading. An oversized line is discarded;
// when its request ID can be read from the retained prefix, an error
// response for that ID takes its place.
type frameFilter struct {
	r         *bufio.Reader
	limit     int
	pending   []byte
	oversized atomic.Uint64
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
				return buf, nil
			}
			return f.substitute(buf), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			if over {
				return f.substitute(buf), err
			}
			return buf, err
		}
	}
}

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
