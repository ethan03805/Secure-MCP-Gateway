package hostile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPFront serves the fixtures over Streamable HTTP (the 2025-11-25
// shape the Gateway's southbound client speaks), so that every row whose
// misbehavior is in its messages can be run against the Gateway's HTTP
// transport (FR-5.28) as well as over stdio. Each initialize starts a new
// fixture instance with its own nonce, identified by an Mcp-Session-Id.
// Each request is answered with an event stream that carries everything
// the fixture writes while the request is open (its notifications, its
// server-initiated requests, and lines that are not JSON) and ends with the
// fixture's response. A line the fixture writes in parts (HF-17) is sent
// only when it is complete, as the stdio reader would see it.
//
// The front listens only on loopback addresses.
type HTTPFront struct {
	cfg Config

	mu       sync.Mutex
	sessions map[string]*frontSession
}

type frontSession struct {
	in     *io.PipeWriter
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	waiters map[*frontWaiter]bool
}

type frontWaiter struct {
	id    string // request ID (compact JSON)
	lines chan []byte
}

// NewHTTPFront returns the handler for fixture c.
func NewHTTPFront(c Config) *HTTPFront {
	return &HTTPFront{cfg: c, sessions: map[string]*frontSession{}}
}

// ListenHTTP serves fixture c on its loopback address c.HTTP until ctx
// ends; ready receives the endpoint URL once the listener is open.
func ListenHTTP(ctx context.Context, c Config, ready func(url string)) error {
	host, _, err := net.SplitHostPort(c.HTTP)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("-http %s: only a loopback address is allowed", c.HTTP)
	}
	ln, err := net.Listen("tcp", c.HTTP)
	if err != nil {
		return err
	}
	f := NewHTTPFront(c)
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	ready("http://" + ln.Addr().String() + "/mcp")
	err = srv.Serve(ln)
	f.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close ends every fixture instance.
func (f *HTTPFront) Close() {
	f.mu.Lock()
	ss := f.sessions
	f.sessions = map[string]*frontSession{}
	f.mu.Unlock()
	for _, s := range ss {
		s.close()
	}
}

func (s *frontSession) close() {
	_ = s.in.Close()
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
	}
}

func compactID(raw json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return string(raw)
	}
	return b.String()
}

func (f *HTTPFront) start() (string, *frontSession) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	nonce := hex.EncodeToString(b)
	c := f.cfg
	c.Nonce = nonce
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	s := &frontSession{in: inW, cancel: cancel, done: make(chan struct{}), waiters: map[*frontWaiter]bool{}}
	go func() {
		_ = Serve(ctx, c, inR, outW)
		_ = outW.Close()
		_ = inR.Close()
	}()
	go func() {
		defer close(s.done)
		rd := bufio.NewReaderSize(outR, 64<<10)
		for {
			line, err := rd.ReadBytes('\n')
			if l := bytes.TrimRight(line, "\r\n"); len(l) > 0 {
				s.route(append([]byte(nil), l...))
			}
			if err != nil {
				return
			}
		}
	}()
	return "hostile-" + nonce, s
}

// route hands a fixture line to the request it answers, or to every open
// request when it is not a response.
func (s *frontSession) route(line []byte) {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	isResp := json.Unmarshal(line, &m) == nil && m.Method == "" && len(m.ID) > 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for w := range s.waiters {
		if isResp && w.id != compactID(m.ID) {
			continue
		}
		select {
		case w.lines <- line:
		default: // the request is not reading; drop rather than block
		}
	}
}

// ServeHTTP implements http.Handler.
func (f *HTTPFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("Mcp-Session-Id")
	switch r.Method {
	case http.MethodDelete:
		f.mu.Lock()
		s := f.sessions[sid]
		delete(f.sessions, sid)
		f.mu.Unlock()
		if s != nil {
			s.close()
		}
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body = bytes.TrimSpace(body)
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(body, &m) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var s *frontSession
	if m.Method == "initialize" {
		sid, s = f.start()
		f.mu.Lock()
		f.sessions[sid] = s
		f.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", sid)
	} else {
		f.mu.Lock()
		s = f.sessions[sid]
		f.mu.Unlock()
		if s == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	isRequest := m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null"
	var wt *frontWaiter
	if isRequest {
		wt = &frontWaiter{id: compactID(m.ID), lines: make(chan []byte, 1024)}
		s.mu.Lock()
		s.waiters[wt] = true
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.waiters, wt)
			s.mu.Unlock()
		}()
	}
	if _, err := s.in.Write(append(body, '\n')); err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !isRequest {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		case line := <-wt.lines:
			if _, err := fmt.Fprintf(w, "data: %s\n\n", line); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
			var resp struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal(line, &resp) == nil && resp.Method == "" && compactID(resp.ID) == wt.id {
				return
			}
		}
	}
}
