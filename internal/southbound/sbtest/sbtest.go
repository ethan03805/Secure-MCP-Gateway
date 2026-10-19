// Package sbtest is a scripted Streamable HTTP MCP server for tests of the
// southbound transport (internal/southbound) and of the elements built on
// it. It speaks JSON-RPC itself, so a test can send what an SDK server
// never would: event streams with comments, responses for another request,
// oversized bodies, broken streams, refusals that are not JSON-RPC.
package sbtest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Msg is one JSON-RPC message the server received.
type Msg struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// Request is one HTTP request the server received.
type Request struct {
	HTTPMethod string
	Header     http.Header
	Body       []byte
	Msg        Msg
}

// Server is the scripted server. Set its fields before the first request.
type Server struct {
	*httptest.Server

	// Tools are the tool definitions tools/list returns (JSON objects).
	Tools []string
	// SSE answers requests with an event stream instead of a JSON body.
	SSE bool
	// Comments are written as SSE comment lines before each event.
	Comments []string
	// CRLF ends SSE lines with CR LF.
	CRLF bool
	// Session, when set, is issued with the initialize response and
	// required on every later request (404 without it, or after Expire).
	Session string
	// ListChanged declares tools.listChanged in initialize.
	ListChanged bool
	// Token, when set, is required as a bearer token (403 with a
	// {"detail": ...} body otherwise, as ContextForge answers).
	Token string
	// Call handles tools/call. It returns the result object (JSON) for
	// the request; nil uses the default, which echoes the arguments as
	// text. A Call may write the response itself with W and return
	// Handled.
	Call func(w *W, m Msg) json.RawMessage
	// Get handles a GET (listen or resumption) stream; nil answers 405.
	Get func(w *W, lastEventID string)

	mu      sync.Mutex
	reqs    []Request
	expired atomic.Bool
	deletes atomic.Int32
}

// Handled is returned by a Call that wrote its own response.
var Handled = json.RawMessage("handled")

// New starts a plain-http server on loopback; NewTLS an https one.
func New() *Server {
	s := &Server{}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// NewTLS starts an https server with a self-signed certificate
// (httptest's); Certificate() returns it.
func NewTLS() *Server {
	s := &Server{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Posts returns the POST requests whose JSON-RPC method is method ("" for
// every POST).
func (s *Server) Posts(method string) []Request {
	var out []Request
	for _, r := range s.Requests() {
		if r.HTTPMethod == http.MethodPost && (method == "" || r.Msg.Method == method) {
			out = append(out, r)
		}
	}
	return out
}

// Expire makes the session unknown: later requests get 404.
func (s *Server) Expire() { s.expired.Store(true) }

// Deletes counts DELETE requests that ended the session.
func (s *Server) Deletes() int { return int(s.deletes.Load()) }

// W writes a response.
type W struct {
	http.ResponseWriter
	r       *http.Request
	s       *Server
	started bool
	n       int
}

// Request returns the HTTP request being answered.
func (w *W) Request() *http.Request { return w.r }

// JSON writes a JSON response with status.
func (w *W) JSON(status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (w *W) nl() string {
	if w.s.CRLF {
		return "\r\n"
	}
	return "\n"
}

// Start begins an event stream.
func (w *W) Start() {
	if w.started {
		return
	}
	w.started = true
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
}

// Event writes one event with the next numeric ID (id "" omits it when
// noID), preceded by the server's comment lines.
func (w *W) Event(data string, noID bool) {
	w.Start()
	nl := w.nl()
	var b strings.Builder
	for _, c := range w.s.Comments {
		b.WriteString(":" + c + nl)
	}
	w.n++
	if !noID {
		b.WriteString("id: " + strconv.Itoa(w.n) + nl)
	}
	b.WriteString("event: message" + nl)
	for _, l := range strings.Split(data, "\n") {
		b.WriteString("data: " + l + nl)
	}
	b.WriteString(nl)
	_, _ = io.WriteString(w, b.String())
	w.Flush()
}

// Raw writes bytes to the stream unchanged.
func (w *W) Raw(s string) {
	w.Start()
	_, _ = io.WriteString(w, s)
	w.Flush()
}

// Flush sends what was written.
func (w *W) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Answer writes the response msg in the server's mode (JSON or SSE).
func (w *W) Answer(msg string) {
	if w.s.SSE {
		w.Event(msg, false)
		return
	}
	w.JSON(http.StatusOK, msg)
}

// Result builds a response with result for id.
func Result(id json.RawMessage, result string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result)
}

// Text builds a CallToolResult with one text item.
func Text(text string) json.RawMessage {
	b, _ := json.Marshal(text)
	return json.RawMessage(`{"content":[{"type":"text","text":` + string(b) + `}]}`)
}

func (s *Server) serve(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	req := Request{HTTPMethod: r.Method, Header: r.Header.Clone(), Body: body}
	_ = json.Unmarshal(body, &req.Msg)
	s.mu.Lock()
	s.reqs = append(s.reqs, req)
	s.mu.Unlock()
	w := &W{ResponseWriter: rw, r: r, s: s}
	if s.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.Token {
		w.JSON(http.StatusForbidden, `{"detail":"Access denied"}`)
		return
	}
	m := req.Msg
	if s.Session != "" && m.Method != "initialize" {
		if s.expired.Load() || r.Header.Get("Mcp-Session-Id") != s.Session {
			w.JSON(http.StatusNotFound, `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"session not found"}}`)
			return
		}
	}
	switch r.Method {
	case http.MethodDelete:
		s.deletes.Add(1)
		rw.WriteHeader(http.StatusOK)
		return
	case http.MethodGet:
		if s.Get == nil {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.Get(w, r.Header.Get("Last-Event-ID"))
		return
	}
	if len(m.ID) == 0 || string(m.ID) == "null" {
		rw.WriteHeader(http.StatusAccepted) // notification or response
		return
	}
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(m.Params, &p)
		if s.Session != "" {
			s.expired.Store(false) // a new session under the same ID
			rw.Header().Set("Mcp-Session-Id", s.Session)
		}
		tools := `{}`
		if s.ListChanged {
			tools = `{"listChanged":true}`
		}
		w.Answer(Result(m.ID, fmt.Sprintf(`{"protocolVersion":%q,"capabilities":{"tools":%s},"serverInfo":{"name":"sbtest","version":"1"}}`, p.ProtocolVersion, tools)))
	case "ping":
		w.Answer(Result(m.ID, `{}`))
	case "tools/list":
		tools := s.Tools
		if tools == nil {
			tools = []string{`{"name":"echo","inputSchema":{"type":"object"}}`}
		}
		w.Answer(Result(m.ID, `{"tools":[`+strings.Join(tools, ",")+`]}`))
	case "tools/call":
		var res json.RawMessage
		if s.Call != nil {
			res = s.Call(w, m)
		}
		if string(res) == string(Handled) {
			return
		}
		if res == nil {
			var p struct {
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			res = Text(string(p.Arguments))
		}
		w.Answer(Result(m.ID, string(res)))
	default:
		w.Answer(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, m.ID))
	}
}
