package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestStreamCloseCancelsWithinOneSecond is FR-1.41: the harness closes the
// SSE response stream of an in-flight tools/call (a request with a
// progress token, answered as an event stream from its first message), and
// notifications/cancelled for the call reaches the backend within 1 second.
func TestStreamCloseCancelsWithinOneSecond(t *testing.T) {
	reqtest.Verifies(t, "FR-1.41")
	ids := make(chan json.RawMessage, 1)
	sc := &scripted{call: func(_ func(string), id json.RawMessage, _ string) bool {
		ids <- id
		return true // never answers
	}}
	h := newScriptedHarness(t, sc, "")
	_, tok := h.session("rw")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"t_w","arguments":{},"_meta":{"progressToken":"p8",%s}}}`, wireMeta)
	req, err := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range wireHeaders(tok, "tools/call") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Mcp-Name", "t_w")
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("not an event stream: %s", resp.Header.Get("Content-Type"))
	}
	var id json.RawMessage
	select {
	case id = <-ids:
	case <-time.After(5 * time.Second):
		t.Fatal("the call was not dispatched")
	}
	closed := time.Now()
	cancel()
	resp.Body.Close()
	for time.Since(closed) < 2*time.Second {
		for _, l := range sc.received() {
			var m struct {
				Method string `json:"method"`
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
				} `json:"params"`
			}
			if json.Unmarshal([]byte(l), &m) == nil && m.Method == "notifications/cancelled" && string(m.Params.RequestID) == string(id) {
				if d := time.Since(closed); d > time.Second {
					t.Fatalf("southbound cancellation after %s", d)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no southbound notifications/cancelled for %s", id)
}
