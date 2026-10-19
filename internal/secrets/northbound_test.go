package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// syncBuffer is the broker harness's diagnostic log: the Gateway writes to
// it from its own goroutines while a test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// northboundSink records every progress notification the harness receives.
type northboundSink struct {
	mu   sync.Mutex
	msgs []string
}

func (s *northboundSink) handler(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(r.Params)
	s.msgs = append(s.msgs, string(b))
}

func (s *northboundSink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

// TestSecretsNeverNorthbound (SR-2-1): a secret delivered in each mode (S4
// launch environment, S3 per-instance file, S2 per-call file, and S1, the
// header the Egress Broker injects, as an upstream echoing it would return
// it) is echoed by the fixture server through every X-01 channel a tool
// call has: the result (raw and Base64), a tool error result, a JSON-RPC
// error and progress notifications. Every byte the harness receives, and
// the evidence and the diagnostic log, is scanned for each value, its
// Base64 form and a 12-byte fragment. Each echo must also be shown to have
// carried the value (a refusal with SECRET_LEAK, or a withheld progress
// message), so that a missing delivery cannot pass the test.
func TestSecretsNeverNorthbound(t *testing.T) {
	reqtest.Verifies(t, "SR-2-1")
	h := newBrokerHarness(t)
	sink := &northboundSink{}
	sess, tok, err := h.store.Create(session.CreateParams{PrincipalID: "cc", ClientID: "c", Listener: "tls", Claims: session.Claims{Template: "all"}})
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: bearerRT{tok.Access, h.srv.Client().Transport}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "secrets-northbound", Version: "1"}, &mcp.ClientOptions{ProgressNotificationHandler: sink.handler}).
		Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: h.srv.URL + "/mcp", HTTPClient: hc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	var harness []string
	seq := 0
	callRaw := func(name string, args map[string]any, progress bool) (*mcp.CallToolResult, *jsonrpc.Error) {
		p := &mcp.CallToolParams{Name: "t_" + name, Arguments: args}
		if progress {
			seq++
			p.Meta = mcp.Meta{"progressToken": fmt.Sprintf("nb-%d", seq)}
		}
		res, err := cs.CallTool(context.Background(), p)
		if err != nil {
			var we *jsonrpc.Error
			if !errors.As(err, &we) {
				t.Fatalf("%s %v: %v", name, args, err)
			}
			b, _ := json.Marshal(we)
			harness = append(harness, string(b))
			return nil, we
		}
		b, _ := json.Marshal(res)
		harness = append(harness, string(b))
		return res, nil
	}
	reason := func(e *jsonrpc.Error) string {
		var d map[string]any
		_ = json.Unmarshal(e.Data, &d)
		s, _ := d["reasonCode"].(string)
		return s
	}
	// Each echo starts from a fresh minute and with no secret suspended by
	// an earlier leak, so that every delivery happens.
	refs := []string{"env-secret", "file-secret", "call-secret", "hdr-secret"}
	fresh := func() {
		h.tv.clock.Advance(2 * time.Minute)
		for _, n := range refs {
			if s := h.tv.v.find(n); s != nil {
				h.broker.Unsuspend(s.Ref)
			}
		}
	}

	modes := []struct{ mode, source string }{{"S4", "API_TOKEN"}, {"S3", "DB_PASS_FILE"}, {"S2", "CALL_KEY_FILE"}, {"S1", "S1"}}
	for _, m := range modes {
		// Result, raw and Base64.
		for _, enc := range []string{"", "b64"} {
			fresh()
			if res, e := callRaw("echoresult", map[string]any{"name": m.source, "enc": enc}, false); e == nil || reason(e) != ReasonLeak {
				t.Errorf("%s result (%q): want a SECRET_LEAK refusal, got %v %v", m.mode, enc, res, e)
			}
		}
		// Tool error result and JSON-RPC error.
		for _, kind := range []string{"tool", "rpc"} {
			fresh()
			if res, e := callRaw("echoerror", map[string]any{"name": m.source, "text": kind}, false); e == nil || reason(e) != ReasonLeak {
				t.Errorf("%s %s error: want a SECRET_LEAK refusal, got %v %v", m.mode, kind, res, e)
			}
		}
		// Progress notifications: the two carrying the value are withheld,
		// the others are relayed.
		fresh()
		before, logBefore := len(sink.all()), strings.Count(h.logs.String(), "withheld by the response filters")
		res, e := callRaw("echoprogress", map[string]any{"name": m.source, "enc": "b64"}, true)
		if e != nil || res == nil || res.IsError {
			t.Errorf("%s progress call: %v %v", m.mode, res, e)
		}
		deadline := time.Now().Add(3 * time.Second)
		for len(sink.all())-before < 2 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		got := sink.all()[before:]
		relayed := strings.Join(got, "\n")
		if !strings.Contains(relayed, "starting") || !strings.Contains(relayed, "half way") {
			t.Errorf("%s progress: the clean notifications were not relayed: %v", m.mode, got)
		}
		if n := strings.Count(h.logs.String(), "withheld by the response filters") - logBefore; n != 2 {
			t.Errorf("%s progress: %d messages withheld, want 2 (the value was not delivered or not detected)", m.mode, n)
		}
	}
	harness = append(harness, sink.all()...)

	// Session API responses (FR-2.2), after every delivery above: this
	// session's record, and the error of a session request with a wrong
	// client secret.
	for _, req := range []struct{ method, path, body string }{
		{"GET", "/smcp/v1/sessions/" + sess.ID, ""},
		{"POST", "/smcp/v1/sessions", `{"client_id":"c","client_secret":"wrong"}`},
	} {
		r, err := http.NewRequest(req.method, h.srv.URL+req.path, strings.NewReader(req.body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if req.method == "GET" && (resp.StatusCode != http.StatusOK || !strings.Contains(string(b), sess.ID)) {
			t.Errorf("session API GET: %d %s", resp.StatusCode, b)
		}
		harness = append(harness, string(b))
	}
	h.assertNoValues(harness...)
}
