package backend

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound/sbtest"
)

// tokenBroker delivers fixed values for the references it is asked for,
// as the Secret Broker's S4 delivery does.
type tokenBroker map[string]string

func (b tokenBroker) Resolve(_ context.Context, req pipeline.SecretRequest) (map[string]string, error) {
	out := map[string]string{}
	for env, ref := range req.Refs {
		v, ok := b[ref]
		if !ok {
			return nil, fmt.Errorf("no secret %q", ref)
		}
		out[env] = v
	}
	return out, nil
}

type httpOpts struct {
	timeout     time.Duration
	resultBytes int64
	secrets     pipeline.SecretBroker
	edit        func(*config.Server)
}

// startHTTP starts a registry with one url server, alias "h".
func startHTTP(t *testing.T, url string, o httpOpts) (*Registry, *pipeline.Capabilities) {
	t.Helper()
	if o.timeout == 0 {
		o.timeout = 5 * time.Second
	}
	if o.resultBytes == 0 {
		o.resultBytes = 1 << 20
	}
	sc := config.Server{Alias: "h", URL: url}
	if o.edit != nil {
		o.edit(&sc)
	}
	caps := pipeline.NewCapabilities(time.Minute)
	r, err := Start(context.Background(), []config.Server{sc}, Options{
		Limits:   Limits{PerPrincipal: 4, Total: 4, Queue: 4, UpstreamTimeout: o.timeout, ResultBytes: o.resultBytes},
		Launcher: southbound.Wrap(nil), Capabilities: caps, Secrets: o.secrets})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r, caps
}

func callText(t *testing.T, r *Registry, caps *pipeline.Capabilities, public, corr, args string) (string, error) {
	t.Helper()
	ref := r.Resolve(public)
	if ref == nil {
		t.Fatalf("no tool %s; have %v", public, r.PublicNames())
	}
	res, err := r.Call(context.Background(), dispatch(caps, ref, corr, args))
	if err != nil {
		return "", err
	}
	if len(res.Content) != 1 {
		return "", fmt.Errorf("content %v", res.Content)
	}
	return res.Content[0].(*mcp.TextContent).Text, nil
}

// TestHTTPRequestHeadersAndResponseTypes: every POST carries Accept with
// both media types, Mcp-Protocol-Version, Mcp-Method and, for tools/call,
// Mcp-Name; a JSON response and an SSE response are both accepted, from
// the scripted fixture and from the SDK's own Streamable HTTP server in
// both of its response modes (FR-5.28).
func TestHTTPRequestHeadersAndResponseTypes(t *testing.T) {
	reqtest.Verifies(t, "FR-5.28")
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("scripted sse=%v", sse), func(t *testing.T) {
			s := sbtest.New()
			t.Cleanup(s.Close)
			s.SSE = sse
			r, caps := startHTTP(t, s.URL+"/mcp", httpOpts{})
			got, err := callText(t, r, caps, "h_echo", "c1", `{"x":1}`)
			if err != nil || got != `{"x":1}` {
				t.Fatalf("result %q %v", got, err)
			}
			posts := s.Posts("")
			if len(posts) < 4 || posts[0].Msg.Method != "initialize" || posts[1].Msg.Method != "notifications/initialized" || posts[2].Msg.Method != "tools/list" {
				t.Fatalf("posts out of order or missing: %d", len(posts))
			}
			for _, p := range posts {
				h := p.Header
				if !strings.Contains(h.Get("Accept"), "application/json") || !strings.Contains(h.Get("Accept"), "text/event-stream") {
					t.Errorf("%s: Accept %q", p.Msg.Method, h.Get("Accept"))
				}
				if h.Get("Mcp-Protocol-Version") != LegacyEra {
					t.Errorf("%s: Mcp-Protocol-Version %q", p.Msg.Method, h.Get("Mcp-Protocol-Version"))
				}
				if h.Get("Mcp-Method") != p.Msg.Method {
					t.Errorf("%s: Mcp-Method %q", p.Msg.Method, h.Get("Mcp-Method"))
				}
				if h.Get("Content-Type") != "application/json" {
					t.Errorf("%s: Content-Type %q", p.Msg.Method, h.Get("Content-Type"))
				}
			}
			call := s.Posts("tools/call")
			if len(call) != 1 || call[0].Header.Get("Mcp-Name") != "echo" {
				t.Fatalf("tools/call headers %v", call)
			}
		})
	}
	for _, jsonResp := range []bool{true, false} {
		t.Run(fmt.Sprintf("sdk json=%v", jsonResp), func(t *testing.T) {
			srv := mcp.NewServer(&mcp.Implementation{Name: "sdk", Version: "1"}, nil)
			type in struct {
				Who string `json:"who"`
			}
			mcp.AddTool(srv, &mcp.Tool{Name: "greet"}, func(_ context.Context, _ *mcp.CallToolRequest, a in) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "hi " + a.Who}}}, nil, nil
			})
			var sessions atomic.Int32
			h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{JSONResponse: jsonResp})
			s := sbtest.New()
			s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Mcp-Session-Id") != "" {
					sessions.Add(1)
				}
				h.ServeHTTP(w, r)
			})
			t.Cleanup(s.Close)
			r, caps := startHTTP(t, s.URL, httpOpts{})
			got, err := callText(t, r, caps, "h_greet", "c1", `{"who":"you"}`)
			if err != nil || got != "hi you" {
				t.Fatalf("result %q %v", got, err)
			}
			if sessions.Load() == 0 {
				t.Fatal("the SDK server's session ID was not sent back")
			}
		})
	}
}

// TestHTTPHeaderMirroringAndEncoding: x-mcp-header parameters are mirrored
// into Mcp-Param-* headers; non-ASCII, padded, sentinel-like and multi-line
// values are Base64-encoded, plain values are not, and absent or null
// values send no header (FR-5.29).
func TestHTTPHeaderMirroringAndEncoding(t *testing.T) {
	reqtest.Verifies(t, "FR-5.29")
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.Tools = []string{`{"name":"q","inputSchema":{"type":"object","properties":{
		"region":{"type":"string","x-mcp-header":"Region"},
		"n":{"type":"integer","x-mcp-header":"N"},
		"on":{"type":"boolean","x-mcp-header":"On"},
		"scope":{"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"Tenant"}}},
		"body":{"type":"string"}}}}`}
	r, caps := startHTTP(t, s.URL, httpOpts{})
	cases := []struct {
		args string
		want map[string]string
	}{
		{`{"region":"us-west1","n":42,"on":true,"scope":{"tenant":"acme"},"body":"x"}`,
			map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-N": "42", "Mcp-Param-On": "true", "Mcp-Param-Tenant": "acme"}},
		{`{"region":"Hello, 世界","scope":{"tenant":" padded "}}`,
			map[string]string{"Mcp-Param-Region": "=?base64?SGVsbG8sIOS4lueVjA==?=", "Mcp-Param-Tenant": "=?base64?IHBhZGRlZCA=?="}},
		{`{"region":"=?base64?literal?=","scope":{"tenant":"line1\nline2"}}`,
			map[string]string{"Mcp-Param-Region": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", "Mcp-Param-Tenant": "=?base64?bGluZTEKbGluZTI=?="}},
		{`{"region":null,"n":-7}`, map[string]string{"Mcp-Param-N": "-7"}},
	}
	for i, c := range cases {
		if _, err := callText(t, r, caps, "h_q", fmt.Sprintf("c%d", i), c.args); err != nil {
			t.Fatal(err)
		}
		calls := s.Posts("tools/call")
		h := calls[len(calls)-1].Header
		got := map[string]string{}
		for k := range h {
			if strings.HasPrefix(k, "Mcp-Param-") {
				got[k] = h.Get(k)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("case %d: headers %v, want %v", i, got, c.want)
		}
	}
}

// TestHTTPSSECommentsIgnored: comment lines before and between events and
// inside an event, with CR LF line ends, do not disturb the call (FR-5.30).
func TestHTTPSSECommentsIgnored(t *testing.T) {
	reqtest.Verifies(t, "FR-5.30")
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.SSE, s.CRLF = true, true
	s.Comments = []string{"", " keep-alive", "data: not data"}
	s.Call = func(w *sbtest.W, m sbtest.Msg) json.RawMessage {
		w.Raw(":\r\n: ping\r\n\r\n")
		w.Event(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"working"}}`, false)
		w.Raw(": between\r\n")
		w.Raw("id: 9\r\n: inside\r\ndata: " + sbtest.Result(m.ID, string(sbtest.Text("done"))) + "\r\n\r\n")
		return sbtest.Handled
	}
	r, caps := startHTTP(t, s.URL, httpOpts{})
	for i := range 3 {
		got, err := callText(t, r, caps, "h_echo", fmt.Sprintf("c%d", i), `{}`)
		if err != nil || got != "done" {
			t.Fatalf("call %d: %q %v", i, got, err)
		}
	}
	if n := r.Servers()["h"].Restarts(); n != 0 {
		t.Fatalf("%d restarts", n)
	}
}

// TestHTTPBoundsAndCorrelation: an oversized JSON or SSE response is
// withheld as ErrTooLarge; a response for another request ID is dropped and
// the call fails; a JSON-RPC batch, a refusal that is not JSON-RPC, a 202
// and an unknown content type each fail only that call.
func TestHTTPBoundsAndCorrelation(t *testing.T) {
	var mode atomic.Value
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.Call = func(w *sbtest.W, m sbtest.Msg) json.RawMessage {
		big := sbtest.Text(strings.Repeat("A", 200<<10))
		switch mode.Load().(string) {
		case "big-json":
			w.JSON(200, sbtest.Result(m.ID, string(big)))
		case "big-sse":
			w.Event(sbtest.Result(m.ID, string(big)), false)
		case "other-id-json":
			w.JSON(200, sbtest.Result(json.RawMessage(`"someone-else"`), string(sbtest.Text("stolen"))))
		case "other-id-sse":
			w.Event(sbtest.Result(json.RawMessage(`999`), string(sbtest.Text("stolen"))), false)
			w.Event(sbtest.Result(m.ID, string(sbtest.Text("mine"))), false)
		case "batch":
			w.JSON(200, "["+sbtest.Result(m.ID, string(sbtest.Text("b")))+"]")
		case "403":
			w.JSON(403, `{"detail":"Access denied"}`)
		case "202":
			w.WriteHeader(202)
		case "html":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html>"))
		default:
			return nil
		}
		return sbtest.Handled
	}
	r, caps := startHTTP(t, s.URL, httpOpts{resultBytes: 16 << 10})
	for _, m := range []string{"big-json", "big-sse"} {
		mode.Store(m)
		if _, err := callText(t, r, caps, "h_echo", m, `{}`); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("%s: got %v", m, err)
		}
	}
	if r.Servers()["h"].OversizedFrames() != 2 {
		t.Fatalf("oversized %d", r.Servers()["h"].OversizedFrames())
	}
	mode.Store("other-id-sse")
	if got, err := callText(t, r, caps, "h_echo", "o1", `{}`); err != nil || got != "mine" {
		t.Fatalf("other-id-sse: %q %v", got, err)
	}
	for _, m := range []string{"other-id-json", "batch", "403", "202", "html"} {
		mode.Store(m)
		_, err := callText(t, r, caps, "h_echo", m, `{}`)
		var be *BackendError
		if !errors.As(err, &be) {
			t.Fatalf("%s: got %v", m, err)
		}
	}
	mode.Store("ok")
	if got, err := callText(t, r, caps, "h_echo", "last", `{"k":"v"}`); err != nil || got != `{"k":"v"}` {
		t.Fatalf("after: %q %v", got, err)
	}
	if n := r.Servers()["h"].Restarts(); n != 0 {
		t.Fatalf("%d restarts", n)
	}
}

// TestHTTPSessionLifecycle: the session ID issued with initialize is sent
// on every later request, an expired session (404) replaces the instance
// with a new session, and closing the registry ends the session with
// DELETE.
func TestHTTPSessionLifecycle(t *testing.T) {
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.Session = "sess-1"
	r, caps := startHTTP(t, s.URL, httpOpts{})
	if _, err := callText(t, r, caps, "h_echo", "c1", `{}`); err != nil {
		t.Fatal(err)
	}
	for _, p := range s.Posts("") {
		if want := map[bool]string{true: "", false: "sess-1"}[p.Msg.Method == "initialize"]; p.Header.Get("Mcp-Session-Id") != want {
			t.Fatalf("%s: session %q", p.Msg.Method, p.Header.Get("Mcp-Session-Id"))
		}
	}
	s.Expire()
	if _, err := callText(t, r, caps, "h_echo", "c2", `{}`); !errors.Is(err, ErrInstanceFailed) {
		t.Fatalf("expired session: %v", err)
	}
	// The relaunch initializes again; the fixture accepts the session
	// again once it is re-issued.
	waitFor(t, func() bool { return len(s.Posts("initialize")) == 2 })
	waitFor(t, func() bool { return r.Servers()["h"].Restarts() == 1 })
	before := s.Deletes()
	r.Close()
	if s.Deletes() <= before {
		t.Fatal("no DELETE when the instance closed")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestHTTPStreamResumption: a response stream that ends after a numbered
// progress event is resumed with GET and Last-Event-ID, and the response
// arrives on the resumed stream; a stream without event IDs is not resumed
// and fails the call.
func TestHTTPStreamResumption(t *testing.T) {
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.SSE = true
	var pending atomic.Value
	var numbered atomic.Bool
	s.Call = func(w *sbtest.W, m sbtest.Msg) json.RawMessage {
		pending.Store(string(m.ID))
		w.Event(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"half"}}`, !numbered.Load())
		return sbtest.Handled // the stream ends without the response
	}
	var lastIDs []string
	s.Get = func(w *sbtest.W, last string) {
		lastIDs = append(lastIDs, last)
		id, _ := pending.Load().(string)
		w.Event(sbtest.Result(json.RawMessage(id), string(sbtest.Text("resumed"))), false)
	}
	r, caps := startHTTP(t, s.URL, httpOpts{})
	numbered.Store(true)
	if got, err := callText(t, r, caps, "h_echo", "c1", `{}`); err != nil || got != "resumed" {
		t.Fatalf("resumed: %q %v", got, err)
	}
	if len(lastIDs) != 1 || lastIDs[0] != "1" {
		t.Fatalf("Last-Event-ID %v", lastIDs)
	}
	numbered.Store(false)
	var be *BackendError
	if _, err := callText(t, r, caps, "h_echo", "c2", `{}`); !errors.As(err, &be) {
		t.Fatalf("unnumbered: %v", err)
	}
}

// TestHTTPTLSAndCredentials: an https server is reached only when its
// certificate verifies against ca_file; the bearer token from the Secret
// Broker reaches the server and never appears in the instance's
// diagnostics; a redirect is not followed.
func TestHTTPTLSAndCredentials(t *testing.T) {
	s := sbtest.NewTLS()
	t.Cleanup(s.Close)
	s.Token = "tok-123456"
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	broker := tokenBroker{"vault:cf": "tok-123456"}
	withToken := func(sc *config.Server) {
		sc.SecretEnv = map[string]string{southbound.TokenEnv: "vault:cf"}
	}
	// Without ca_file the self-signed certificate does not verify.
	caps := pipeline.NewCapabilities(time.Minute)
	sc := config.Server{Alias: "h", URL: s.URL}
	withToken(&sc)
	_, err := Start(context.Background(), []config.Server{sc}, Options{Limits: Limits{PerPrincipal: 1, Total: 1, UpstreamTimeout: time.Second, ResultBytes: 1 << 20},
		Launcher: southbound.Wrap(nil), Capabilities: caps, Secrets: broker})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unverified TLS: %v", err)
	}
	r, caps := startHTTP(t, s.URL, httpOpts{secrets: broker, edit: func(sc *config.Server) { withToken(sc); sc.CAFile = ca }})
	if _, err := callText(t, r, caps, "h_echo", "c1", `{}`); err != nil {
		t.Fatal(err)
	}
	for _, p := range s.Requests() {
		if p.Header.Get("Authorization") != "Bearer tok-123456" {
			t.Fatalf("%s %s without the token", p.HTTPMethod, p.Msg.Method)
		}
	}
	// A refused token is a backend error whose text stays out of the
	// result; the diagnostics never hold the token.
	s.Token = "rotated"
	var be *BackendError
	if _, err := callText(t, r, caps, "h_echo", "c2", `{}`); !errors.As(err, &be) {
		t.Fatalf("refused token: %v", err)
	}
	if strings.Contains(r.Servers()["h"].Stderr(), "tok-123456") {
		t.Fatal("diagnostics hold the token")
	}

	// Redirects are not followed, so the token never reaches the target.
	var hits atomic.Int32
	target := sbtest.New()
	t.Cleanup(target.Close)
	target.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(500) })
	redir := sbtest.New()
	t.Cleanup(redir.Close)
	redir.Config.Handler = http.RedirectHandler(target.URL, http.StatusTemporaryRedirect)
	_, err = Start(context.Background(), []config.Server{{Alias: "r", URL: redir.URL, SecretEnv: map[string]string{southbound.TokenEnv: "vault:cf"}}},
		Options{Limits: Limits{PerPrincipal: 1, Total: 1, UpstreamTimeout: time.Second, ResultBytes: 1 << 20}, Launcher: southbound.Wrap(nil), Capabilities: caps, Secrets: broker})
	if err == nil || hits.Load() != 0 {
		t.Fatalf("redirect: err %v, target hit %d times", err, hits.Load())
	}
}

// TestHTTPServerFailures: a server-initiated request on a response stream
// is refused with -32601 (FR-5.20 as for stdio); a server that stops
// answering times the call out and the instance is replaced; an endpoint
// that refuses connections fails the call as a failed instance; a
// high-risk class is refused for a url server.
func TestHTTPServerFailures(t *testing.T) {
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.SSE = true
	var hang atomic.Bool
	s.Call = func(w *sbtest.W, m sbtest.Msg) json.RawMessage {
		if hang.Load() {
			<-w.Request().Context().Done()
			return sbtest.Handled
		}
		w.Event(`{"jsonrpc":"2.0","id":"srv-1","method":"roots/list"}`, false)
		w.Event(sbtest.Result(m.ID, string(sbtest.Text("ok"))), false)
		return sbtest.Handled
	}
	r, caps := startHTTP(t, s.URL, httpOpts{timeout: 300 * time.Millisecond})
	if got, err := callText(t, r, caps, "h_echo", "c1", `{}`); err != nil || got != "ok" {
		t.Fatalf("%q %v", got, err)
	}
	waitFor(t, func() bool {
		for _, p := range s.Posts("") {
			if string(p.Msg.ID) == `"srv-1"` && strings.Contains(string(p.Msg.Error), "-32601") {
				return true
			}
		}
		return false
	})
	if r.Servers()["h"].RefusedRequests() != 1 {
		t.Fatalf("refused %d", r.Servers()["h"].RefusedRequests())
	}
	hang.Store(true)
	if _, err := callText(t, r, caps, "h_echo", "c2", `{}`); !errors.Is(err, ErrTimeout) {
		t.Fatalf("hang: %v", err)
	}
	waitFor(t, func() bool { return r.Servers()["h"].Restarts() == 1 })
	hang.Store(false)
	s.Close() // the endpoint is gone
	if _, err := callText(t, r, caps, "h_echo", "c3", `{}`); !errors.Is(err, ErrInstanceFailed) {
		t.Fatalf("closed endpoint: %v", err)
	}
	high := []config.Server{{Alias: "x", URL: "http://127.0.0.1:1/mcp", RiskClasses: []string{"code-execution"}}}
	if _, err := Start(context.Background(), high, Options{Limits: Limits{PerPrincipal: 1, Total: 1}, Launcher: southbound.Wrap(memLauncher{confined: true}), Capabilities: caps}); !errors.Is(err, ErrHighRiskUnconfined) {
		t.Fatalf("high risk: %v", err)
	}
}
