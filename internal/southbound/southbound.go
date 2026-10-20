// Package southbound is the Tool Dispatcher's (E-10) Streamable HTTP
// client for server instances that are reached over HTTP rather than
// launched as stdio processes (FR-5.28 to FR-5.30, I-13): a loopback server
// such as the bundled ContextForge instance (FR-22.36), or a remote https
// endpoint.
//
// A Conn is a pipeline.Process. The dispatcher writes newline-delimited
// JSON-RPC to it and reads newline-delimited JSON-RPC from it, exactly as
// it does with a stdio instance, so every protection of the stdio path
// applies unchanged: the frame filter's line bound, UTF-8 and JSON-RPC
// checks (FR-5.13, FR-5.14), refusal of server-initiated requests (FR-5.20),
// InputRequiredResult and resultType screening (FR-5.23, FR-5.24), progress
// routing, server-asserted evidence, the upstream timeout and the restart
// and crash-limit rules. Policy, inspection, approvals and the journal sit
// in front of the dispatcher and do not see the transport.
//
// Each message the dispatcher writes becomes one POST (FR-5.28) with
// Accept: application/json, text/event-stream, Mcp-Protocol-Version,
// Mcp-Method, and Mcp-Name for tools/call, prompts/get and resources/read.
// Arguments of a tools/call whose input schema marks them with
// x-mcp-header are mirrored into Mcp-Param-{name} headers, and Mcp-Name and
// Mcp-Param-* values are Base64-encoded when they are not plain header text
// (FR-5.29); the schemas are learned from the tools/list responses that pass
// through the Conn. A JSON response and an SSE response are both accepted;
// SSE comment lines are ignored (FR-5.30).
//
// Correlation (F-24): a response body or response stream answers only the
// request it was opened for. A response with another ID is dropped and, if
// the request gets no answer, an error is returned for it; a JSON-RPC batch
// is refused. Bounds: each message is bounded by MaxMessageBytes while it is
// read (an oversized response is replaced by the frame filter's
// result-too-large error, FR-4.10); response headers by 64 KiB.
//
// Sessions (the 2025-11-25 era the dispatcher negotiates, FR-5.19): an
// Mcp-Session-Id issued with the initialize response is sent on every later
// request and ended with DELETE when the Conn closes; an HTTP 404 for a
// request in a session ends the Conn, and the dispatcher replaces the
// instance with a new session. A response stream that ends before its
// response is resumed with GET and Last-Event-ID (at most three times) when
// the server numbered its events. When the server declares
// tools.listChanged, a GET stream carries its list-change notifications to
// the dispatcher's drift check (SR-3.8-1).
//
// Transport security: https is verified against the system roots or, with
// CAFile, only against the roots in that file; plain http is accepted only
// to a loopback host. Redirects are never followed and proxy variables of
// the environment are ignored. The bearer token (no OAuth client in v1.3.0)
// is delivered by the Secret Broker and is sent only to the configured
// endpoint; it never appears in diagnostics.
package southbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// DefaultMaxMessageBytes bounds one message when Endpoint.MaxMessageBytes is
// zero.
const DefaultMaxMessageBytes = 16 << 20

// maxResumes bounds the resumptions of one response stream.
const maxResumes = 3

// maxRetryWait bounds the reconnection delay a server asks for.
const maxRetryWait = 5 * time.Second

// Endpoint describes one Streamable HTTP server instance.
type Endpoint struct {
	// URL is the MCP endpoint (CheckURL).
	URL string
	// Token, when not empty, is sent as Authorization: Bearer.
	Token string
	// CAFile, when set, names PEM certificates that are the only roots
	// trusted for an https endpoint.
	CAFile string
	// MaxMessageBytes bounds each message read from the server; zero is
	// DefaultMaxMessageBytes.
	MaxMessageBytes int
	// HTTP replaces the client built from CAFile (tests). It must not
	// follow redirects.
	HTTP *http.Client
}

// NewHTTPClient returns the client the transport uses: no proxy, no
// redirects, TLS 1.2 or later verified against the system roots or only
// the roots in caFile, bounded connection setup and response headers.
func NewHTTPClient(caFile string) (*http.Client, error) { return newHTTPClient(caFile, false) }

// newHTTPClient builds the client; guard refuses connections to the
// addresses of refusedAddr (for an endpoint whose host is a name or a
// public address).
func newHTTPClient(caFile string, guard bool) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // operator-configured path
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no PEM certificate", caFile)
		}
		tc.RootCAs = pool
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer(guard).DialContext,
			TLSClientConfig:        tc,
			TLSHandshakeTimeout:    10 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConnsPerHost:    8,
			IdleConnTimeout:        90 * time.Second,
			ForceAttemptHTTP2:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func dialer(guard bool) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if guard {
		// The check runs on the address actually dialed, after name
		// resolution, so a name that resolves (or rebinds) to a refused
		// address is caught.
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if why := refusedAddr(ip); why != "" {
				return fmt.Errorf("southbound: %s resolves to a %s address; use a loopback URL for a local server", address, why)
			}
			return nil
		}
	}
	return d
}

// cloudMetadata are instance-metadata addresses outside link-local.
var cloudMetadata = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("192.0.0.192"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd20:ce::254"),
}

// refusedAddr names the class of an address a url server whose URL does not
// name loopback must not reach: loopback (a local service reached through
// a public name, DNS rebinding), link-local (including 169.254.169.254),
// cloud metadata, multicast and unspecified. Private ranges stay allowed,
// for servers on the local network.
func refusedAddr(ip netip.Addr) string {
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Zone() != "":
		return "link-local"
	case ip.IsMulticast() || ip.IsInterfaceLocalMulticast():
		return "multicast"
	case ip.IsUnspecified():
		return "unspecified"
	}
	for _, m := range cloudMetadata {
		if ip == m {
			return "cloud-metadata"
		}
	}
	return ""
}

// Conn is one connection to a Streamable HTTP server, presented as a
// pipeline.Process.
type Conn struct {
	url   string
	token string
	limit int
	http  *http.Client
	ctx   context.Context
	stop  context.CancelFunc

	pr *io.PipeReader
	pw *io.PipeWriter

	inMu sync.Mutex
	in   []byte // partial line written by the dispatcher

	outMu sync.Mutex

	mu          sync.Mutex
	negotiated  string
	sessionID   string
	listChanged bool
	listening   bool
	tools       map[string][]headerParam
	inflight    map[string]context.CancelFunc

	wg        sync.WaitGroup
	closed    bool // guarded by mu; no goroutine starts once set
	closeOnce sync.Once
	failOnce  sync.Once
	diag      pipeline.Ring
	oversized atomic.Uint64
}

// Dial checks the endpoint and returns its Conn. Nothing is sent until the
// dispatcher writes its initialize request.
func Dial(ep Endpoint) (*Conn, error) {
	u, err := CheckURL(ep.URL)
	if err != nil {
		return nil, err
	}
	h := ep.HTTP
	if h == nil {
		if h, err = newHTTPClient(ep.CAFile, !IsLoopbackHost(u.Hostname())); err != nil {
			return nil, err
		}
	}
	limit := ep.MaxMessageBytes
	if limit <= 0 {
		limit = DefaultMaxMessageBytes
	}
	ctx, stop := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	return &Conn{url: u.String(), token: ep.Token, limit: limit, http: h, ctx: ctx, stop: stop, pr: pr, pw: pw,
		tools: map[string][]headerParam{}, inflight: map[string]context.CancelFunc{}, diag: pipeline.Ring{Max: 16 << 10}}, nil
}

// Read returns the server's messages, one per line.
func (c *Conn) Read(p []byte) (int, error) { return c.pr.Read(p) }

// Write takes newline-delimited JSON-RPC messages and sends each one.
func (c *Conn) Write(b []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	c.inMu.Lock()
	c.in = append(c.in, b...)
	var lines [][]byte
	for {
		i := bytes.IndexByte(c.in, '\n')
		if i < 0 {
			break
		}
		if l := bytes.TrimSpace(c.in[:i]); len(l) > 0 {
			lines = append(lines, append([]byte(nil), l...))
		}
		c.in = c.in[i+1:]
	}
	if len(c.in) > c.limit {
		c.in = nil
		c.inMu.Unlock()
		return 0, errors.New("southbound: message longer than the bound")
	}
	c.inMu.Unlock()
	for _, l := range lines {
		c.send(l)
	}
	return len(b), nil
}

// Close ends the session (DELETE, when the server issued one), cancels
// every request in flight and ends Read.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		sid := c.sessionID
		c.mu.Unlock()
		c.stop()
		if sid != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url, nil); err == nil {
				c.authorize(req.Header)
				req.Header.Set(HeaderSession, sid)
				if resp, err := c.http.Do(req); err == nil {
					drain(resp)
				}
			}
			cancel()
		}
		_ = c.pw.Close()
		c.wg.Wait()
		c.http.CloseIdleConnections()
	})
	return nil
}

// Stderr returns the transport's recent diagnostics: refused or failed
// requests and what the server answered. It never holds the token.
func (c *Conn) Stderr() string { return c.diag.Tail() }

// StderrSince implements pipeline.StderrReader, so the diagnostics become
// server-asserted evidence (SR-6.18-1) like a stdio server's stderr.
func (c *Conn) StderrSince(off uint64) (string, uint64, uint64) { return c.diag.Since(off) }

// OversizedFrames returns how many messages exceeded the bound.
func (c *Conn) OversizedFrames() uint64 { return c.oversized.Load() }

// SessionID returns the server-issued session ID, or "".
func (c *Conn) SessionID() string { return c.session() }

func (c *Conn) session() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// spawn runs fn on its own goroutine unless the Conn is closed.
func (c *Conn) spawn(fn func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		fn()
	}()
	return true
}

func (c *Conn) logf(format string, args ...any) {
	fmt.Fprintf(&c.diag, "southbound: "+format+"\n", args...)
}

// fail ends the connection: the dispatcher sees the instance end and
// replaces it.
func (c *Conn) fail(err error) {
	c.failOnce.Do(func() {
		c.logf("connection ended: %v", err)
		c.stop()
		_ = c.pw.Close()
	})
}

// envelope is the part of a message the transport reads.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type params struct {
	Name            string          `json:"name"`
	URI             string          `json:"uri"`
	Cursor          string          `json:"cursor"`
	ProtocolVersion string          `json:"protocolVersion"`
	Arguments       json.RawMessage `json:"arguments"`
	RequestID       json.RawMessage `json:"requestId"`
	Meta            map[string]any  `json:"_meta"`
}

func (e envelope) params() params {
	var p params
	if len(e.Params) > 0 {
		// Fields of another type (a non-string name) are left empty.
		_ = json.Unmarshal(e.Params, &p)
	}
	return p
}

func hasID(id json.RawMessage) bool { return len(id) > 0 && string(id) != "null" }

// idKey is the canonical text of a JSON-RPC ID.
func idKey(id json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, id) != nil {
		return string(id)
	}
	return b.String()
}

// send dispatches one message the dispatcher wrote.
func (c *Conn) send(msg []byte) {
	var env envelope
	if json.Unmarshal(msg, &env) != nil {
		c.logf("dropped a message the dispatcher wrote that is not a JSON-RPC object")
		return
	}
	switch {
	case env.Method == "":
		// A response to a server-initiated request (ping, or the
		// dispatcher's -32601 refusal, FR-5.20).
		c.postNow(msg, env)
	case !hasID(env.ID):
		if env.Method == "notifications/cancelled" {
			// Closing the response stream is the cancellation on this
			// transport; the 2025-11-25 era also takes the notification.
			if p := env.params(); hasID(p.RequestID) {
				c.mu.Lock()
				cancel := c.inflight[idKey(p.RequestID)]
				c.mu.Unlock()
				if cancel != nil {
					defer cancel()
				}
			}
		}
		c.postNow(msg, env)
	default:
		ctx, cancel := context.WithCancel(c.ctx)
		key := idKey(env.ID)
		c.mu.Lock()
		c.inflight[key] = cancel
		c.mu.Unlock()
		started := c.spawn(func() {
			defer func() {
				c.mu.Lock()
				delete(c.inflight, key)
				c.mu.Unlock()
				cancel()
			}()
			c.request(ctx, msg, env)
		})
		if !started {
			cancel()
		}
	}
}

// postNow sends a notification or response and waits for the server's
// 202, so that messages keep the order the dispatcher wrote them in
// (notifications/initialized before the next request).
func (c *Conn) postNow(msg []byte, env envelope) {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	resp, err := c.post(ctx, msg, env)
	if err != nil {
		if c.ctx.Err() == nil {
			c.logf("%s not delivered: %v", describe(env), err)
		}
		return
	}
	drain(resp)
	if resp.StatusCode/100 != 2 {
		c.logf("%s answered HTTP %d", describe(env), resp.StatusCode)
		return
	}
	if env.Method == "notifications/initialized" {
		c.startListen()
	}
}

func describe(env envelope) string {
	if env.Method == "" {
		return "response"
	}
	return env.Method
}

func (c *Conn) authorize(h http.Header) {
	if c.token != "" {
		h.Set("Authorization", "Bearer "+c.token)
	}
}

// post sends one message with the FR-5.28 and FR-5.29 headers.
func (c *Conn) post(ctx context.Context, msg []byte, env envelope) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	c.authorize(h)
	p := env.params()
	c.mu.Lock()
	version, sid := c.negotiated, c.sessionID
	var hp []headerParam
	if env.Method == "tools/call" {
		hp = c.tools[p.Name]
	}
	c.mu.Unlock()
	if v, ok := p.Meta["io.modelcontextprotocol/protocolVersion"].(string); ok && v != "" {
		version = v
	} else if env.Method == "initialize" {
		version = p.ProtocolVersion
	}
	if version != "" {
		h.Set(HeaderProtocolVersion, version)
	}
	if sid != "" && env.Method != "initialize" {
		h.Set(HeaderSession, sid)
	}
	if env.Method != "" {
		h.Set(HeaderMethod, env.Method)
	}
	switch env.Method {
	case "tools/call", "prompts/get":
		h.Set(HeaderName, EncodeValue(p.Name))
	case "resources/read":
		h.Set(HeaderName, EncodeValue(p.URI))
	}
	setParamHeaders(h, hp, p.Arguments)
	return c.http.Do(req)
}

// request sends one request and delivers its response.
func (c *Conn) request(ctx context.Context, msg []byte, env envelope) {
	resp, err := c.post(ctx, msg, env)
	if err != nil {
		if ctx.Err() != nil {
			return // cancelled, or the Conn closed
		}
		// The endpoint cannot be reached, or TLS verification failed: the
		// instance has failed, as a stdio process that exited has.
		c.fail(fmt.Errorf("%s: %w", env.Method, err))
		return
	}
	defer drain(resp)
	if env.Method == "initialize" && resp.StatusCode/100 == 2 {
		if sid := resp.Header.Get(HeaderSession); sid != "" {
			if !visibleASCII(sid) || len(sid) > 1024 {
				c.fail(errors.New("the server issued a session ID that is not visible ASCII of at most 1024 bytes"))
				return
			}
			c.mu.Lock()
			c.sessionID = sid
			c.mu.Unlock()
		}
	}
	switch {
	case resp.StatusCode == http.StatusNotFound && c.session() != "" && env.Method != "initialize":
		c.fail(errors.New("the server ended the session (HTTP 404)"))
		return
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent:
		c.reply(env.ID, fmt.Sprintf("the server answered HTTP %d without a response", resp.StatusCode))
		return
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
		b, over, err := readBounded(resp.Body, c.limit)
		switch {
		case over:
			c.tooLarge(env)
		case err != nil:
			if ctx.Err() == nil {
				c.reply(env.ID, "reading the response failed: "+err.Error())
			}
		case resp.StatusCode >= 300 && !looksJSONRPC(b):
			// A refusal whose body is not JSON-RPC (ContextForge answers a
			// refused token scope with HTTP 403 {"detail": ...}).
			c.reply(env.ID, fmt.Sprintf("the server answered HTTP %d: %s", resp.StatusCode, snippet(b)))
		default:
			c.answer(env, b, true)
		}
	case "text/event-stream":
		c.stream(ctx, resp.Body, env)
	default:
		b, _, _ := readBounded(resp.Body, 512)
		c.reply(env.ID, fmt.Sprintf("the server answered HTTP %d with content type %q: %s", resp.StatusCode, mt, snippet(b)))
	}
}

// answer handles one message received for request env. It returns true
// when the message was the response to env. final marks a JSON response
// body, which must be that response.
func (c *Conn) answer(env envelope, data []byte, final bool) bool {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		c.reply(env.ID, "the server sent a JSON-RPC batch, which the negotiated protocol version does not allow")
		return true
	}
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	var line bytes.Buffer
	if json.Compact(&line, data) != nil || json.Unmarshal(data, &m) != nil {
		// FR-5.14: the frame filter ends the instance on a line that is not
		// JSON-RPC; the marker line is never valid JSON.
		c.emit([]byte("!southbound: invalid message from the server"))
		return true
	}
	if m.Method != "" {
		if final {
			c.reply(env.ID, "the server answered with a "+m.Method+" message instead of a response")
			return true
		}
		// A notification or server-initiated request on the response
		// stream: the frame filter routes or refuses it (FR-5.20).
		c.emit(line.Bytes())
		return false
	}
	if !hasID(m.ID) {
		var e struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		}
		if len(m.Error) > 0 && json.Unmarshal(m.Error, &e) == nil && e.Code != 0 {
			c.replyCode(env.ID, e.Code, e.Message)
		} else {
			c.reply(env.ID, "the server answered with a response that has no ID")
		}
		return true
	}
	if idKey(m.ID) != idKey(env.ID) {
		// F-24: a stream answers only its own request.
		c.logf("dropped a response for request %s received for request %s (%s)", snippet(m.ID), snippet(env.ID), env.Method)
		if final {
			c.reply(env.ID, "the server answered with a response for another request")
			return true
		}
		return false
	}
	if len(m.Error) == 0 {
		c.learn(env, m.Result)
	}
	c.emit(line.Bytes())
	return true
}

// learn records the negotiated version and declared capabilities from
// initialize and the x-mcp-header annotations from tools/list.
func (c *Conn) learn(env envelope, result json.RawMessage) {
	switch env.Method {
	case "initialize":
		var r struct {
			ProtocolVersion string `json:"protocolVersion"`
			Capabilities    struct {
				Tools *struct {
					ListChanged bool `json:"listChanged"`
				} `json:"tools"`
			} `json:"capabilities"`
		}
		if json.Unmarshal(result, &r) == nil {
			c.mu.Lock()
			c.negotiated = r.ProtocolVersion
			c.listChanged = r.Capabilities.Tools != nil && r.Capabilities.Tools.ListChanged
			c.mu.Unlock()
		}
	case "tools/list":
		var r struct {
			Tools []struct {
				Name        string          `json:"name"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		}
		if json.Unmarshal(result, &r) != nil {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if env.params().Cursor == "" {
			c.tools = map[string][]headerParam{}
		}
		for _, t := range r.Tools {
			if hp, ok := headerParams(t.InputSchema); ok && len(hp) > 0 {
				c.tools[t.Name] = hp
			} else {
				delete(c.tools, t.Name)
			}
		}
	}
}

// stream reads a response stream until the response to env arrives,
// resuming it when it ends early and the server numbered its events.
func (c *Conn) stream(ctx context.Context, body io.ReadCloser, env envelope) {
	last := ""
	for resumes := 0; ; resumes++ {
		var retry time.Duration
		done := c.readEvents(body, func(ev event) bool {
			if ev.ID != "" {
				last = ev.ID
			}
			if ev.Retry > 0 {
				retry = ev.Retry
			}
			if ev.Oversized {
				c.tooLarge(env)
				return true
			}
			if ev.Data == nil {
				return false
			}
			return c.answer(env, ev.Data, false)
		})
		_ = body.Close()
		if done || ctx.Err() != nil {
			return
		}
		if last == "" || resumes >= maxResumes {
			c.reply(env.ID, "the response stream ended before the response")
			return
		}
		if !sleep(ctx, min(retry, maxRetryWait)) {
			return
		}
		resp, err := c.get(ctx, last) //nolint:bodyclose // closed at the top of the next iteration
		if err != nil {
			if ctx.Err() == nil {
				c.reply(env.ID, "the response stream ended and could not be resumed: "+err.Error())
			}
			return
		}
		body = resp.Body
	}
}

// readEvents passes each event of body to fn until fn returns true (done)
// or the stream ends.
func (c *Conn) readEvents(body io.Reader, fn func(event) bool) bool {
	rd := newSSEReader(body, c.limit)
	for {
		ev, err := rd.Next()
		if err != nil {
			return false
		}
		if fn(ev) {
			return true
		}
	}
}

// get opens a GET event stream, resuming after lastID when it is set.
func (c *Conn) get(ctx context.Context, lastID string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("Accept", "text/event-stream")
	c.authorize(h)
	c.mu.Lock()
	if c.negotiated != "" {
		h.Set(HeaderProtocolVersion, c.negotiated)
	}
	if c.sessionID != "" {
		h.Set(HeaderSession, c.sessionID)
	}
	c.mu.Unlock()
	if lastID != "" {
		h.Set("Last-Event-ID", lastID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mt != "text/event-stream" {
		drain(resp)
		return nil, fmt.Errorf("GET answered HTTP %d (%s)", resp.StatusCode, mt)
	}
	return resp, nil
}

// startListen opens the GET stream for server notifications when the
// server declared tools.listChanged; list-change notifications reach the
// dispatcher's drift check. The stream is reopened after it ends, with a
// growing delay, and given up after five failures in a row.
func (c *Conn) startListen() {
	c.mu.Lock()
	if !c.listChanged || c.listening {
		c.mu.Unlock()
		return
	}
	c.listening = true
	c.mu.Unlock()
	c.spawn(func() {
		last, failures := "", 0
		for c.ctx.Err() == nil && failures < 5 {
			resp, err := c.get(c.ctx, last)
			if err != nil {
				failures++
				if c.ctx.Err() == nil {
					c.logf("server notification stream: %v", err)
				}
				if !sleep(c.ctx, time.Duration(failures)*time.Second) {
					return
				}
				continue
			}
			got := false
			c.readEvents(resp.Body, func(ev event) bool {
				if ev.ID != "" {
					last = ev.ID
				}
				if ev.Oversized {
					c.oversized.Add(1)
					c.logf("server notification stream: dropped an oversized event")
					return false
				}
				if ev.Data == nil {
					return false
				}
				got = true
				var m struct {
					Method string `json:"method"`
				}
				var line bytes.Buffer
				if json.Compact(&line, ev.Data) != nil || json.Unmarshal(ev.Data, &m) != nil || m.Method == "" {
					// Responses do not belong on this stream; invalid data
					// ends the instance like an invalid stdout line.
					if m.Method == "" && json.Valid(ev.Data) {
						c.logf("server notification stream: dropped a message that is not a request or notification")
						return false
					}
					c.emit([]byte("!southbound: invalid message from the server"))
					return true
				}
				c.emit(line.Bytes())
				return false
			})
			_ = resp.Body.Close()
			if got {
				failures = 0
			} else {
				failures++
			}
			if !sleep(c.ctx, time.Duration(failures)*time.Second) {
				return
			}
		}
	})
}

// emit writes one line for the dispatcher.
func (c *Conn) emit(line []byte) {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	_, _ = c.pw.Write(append(line, '\n'))
}

// reply answers request id with a transport error (-32603) the dispatcher
// reports as a backend error; msg becomes server-asserted evidence.
func (c *Conn) reply(id json.RawMessage, msg string) {
	c.replyCode(id, -32603, "southbound: "+msg)
}

func (c *Conn) replyCode(id json.RawMessage, code int64, msg string) {
	if !hasID(id) {
		return
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
	c.emit(b)
}

// tooLarge replaces an oversized response with the frame filter's
// result-too-large error (FR-4.10).
func (c *Conn) tooLarge(env envelope) {
	c.oversized.Add(1)
	c.logf("%s: response larger than %d bytes withheld", env.Method, c.limit)
	c.emit(pipeline.ResultTooLargeResponse(env.ID))
}

// readBounded reads at most limit bytes; over reports a longer body.
func readBounded(r io.Reader, limit int) (b []byte, over bool, err error) {
	b, err = io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if len(b) > limit {
		return nil, true, nil
	}
	return b, false, err
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

func looksJSONRPC(b []byte) bool {
	var m struct {
		JSONRPC string `json:"jsonrpc"`
	}
	return json.Unmarshal(b, &m) == nil && m.JSONRPC == "2.0"
}

// snippet is the start of a body for a diagnostic, as valid UTF-8.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return strings.ToValidUTF8(s, "?")
}

func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return s != ""
}

// sleep waits d or until ctx ends; it reports whether ctx is still live.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
