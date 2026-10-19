//go:build hostile

package hostile

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound/sbtest"
)

// httpRows are the Appendix L rows whose misbehavior is in the server's
// messages, so they apply to a server reached over Streamable HTTP. The
// others need a local process (HF-08 and HF-09 a delivered secret file,
// HF-20 to HF-24 the sandbox) or a signed package (HF-03, HF-13), and a
// url server is neither.
var httpRows = map[string]rowCheck{
	"HF-01": checks["HF-01"], "HF-02": checks["HF-02"], "HF-04": checks["HF-04"], "HF-05": checks["HF-05"],
	"HF-06": checks["HF-06"], "HF-07": checks["HF-07"], "HF-10": checks["HF-10"], "HF-11": checks["HF-11"],
	"HF-12": checks["HF-12"], "HF-14": checks["HF-14"], "HF-15": checks["HF-15"], "HF-16": checks["HF-16"],
	"HF-17": checks["HF-17"], "HF-18": invalidOutputHTTP, "HF-19": checks["HF-19"], "HF-25": checks["HF-25"],
	"HF-26": serverRequestsHTTP, "HF-27": checks["HF-27"],
	// Transport rows, not in Appendix L.
	"HTTP-ID":       crossResponseHTTP,
	"HTTP-REDIRECT": redirectHTTP,
	"HTTP-COMMENTS": commentFloodHTTP,
}

// TestHostileHTTPFixtures runs the fixtures over the southbound Streamable
// HTTP transport (FR-5.28): each fixture is served by HTTPFront and
// configured as a url server, and each row must reach the same outcome as
// over stdio. Unlike TestHostileFixtures, a row that does not pass fails
// the test: these defenses exist in both profiles.
func TestHostileHTTPFixtures(t *testing.T) {
	transportHTTP = true
	t.Cleanup(func() { transportHTTP = false })
	for _, id := range sortedKeys(httpRows) {
		t.Run(id, func(t *testing.T) {
			observed, pass := httpRows[id](t)
			t.Logf("%s over HTTP pass=%v: %s", id, pass, observed)
			if !pass {
				t.Errorf("%s over HTTP: %s", id, observed)
			}
		})
	}
}

// invalidOutputHTTP: a server message that is not JSON (HF-18) ends the
// connection: the call fails with -31007, the instance is replaced (a new
// session) and the refusal is recorded.
func invalidOutputHTTP(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-18")}})
	cs, _ := g.client(nil)
	before := g.instance(cs, "h")
	o := g.call(cs, "h_garble", map[string]any{}, nil)
	after := g.instance(cs, "h")
	_, event := g.waitEvent(time.Second, func(e audit.Event) bool {
		return e.CorrelationID == correlation(o) && e.Class != "filter" && (e.ReasonCode != "" || e.Outcome == "terminated")
	})
	var n note
	n.add("call: %s", o)
	n.add("instance replaced: %v", before != "" && after != "" && before != after)
	n.add("refusal event recorded: %v", event)
	return n.String(), o.code == -31007 && before != "" && after != "" && before != after && event
}

// serverRequestsHTTP (HF-26): server-initiated requests on the response
// stream are refused with -32601 and never relayed northbound; a JSON-RPC
// batch, which the negotiated version does not allow on HTTP, fails the
// call without any member reaching the client.
func serverRequestsHTTP(t *testing.T) (string, bool) {
	g := mustStart(t, gwSpec{servers: []serverSpec{hostileServer("HF-26")}})
	var mu sync.Mutex
	north := 0
	cs, _ := g.client(&mcp.ClientOptions{CreateMessageHandler: func(context.Context, *mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) { //nolint:staticcheck // HF-26
		mu.Lock()
		north++
		mu.Unlock()
		return &mcp.CreateMessageResult{Content: &mcp.TextContent{Text: "no"}, Model: "none", Role: "assistant"}, nil //nolint:staticcheck // HF-26
	}})
	o := g.call(cs, "h_legacy", map[string]any{}, nil)
	b := g.call(cs, "h_legacy_batch", map[string]any{}, nil)
	mu.Lock()
	defer mu.Unlock()
	var n note
	n.add("fixture saw: %q (%s)", o.text, o)
	n.add("batch: %s", b)
	n.add("sampling requests relayed to the client: %d", north)
	return n.String(), o.code == 0 && strings.Contains(o.text, "roots/list=error(-32601)") && !strings.Contains(o.text, "=answered") &&
		b.code != 0 && north == 0
}

// crossResponseHTTP: a server answers a call's stream with a response for
// another request ID carrying its own content, then the real response.
// The foreign response is dropped; the caller gets only its own result.
func crossResponseHTTP(t *testing.T) (string, bool) {
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.SSE = true
	s.Call = func(w *sbtest.W, m sbtest.Msg) json.RawMessage {
		w.Event(sbtest.Result(json.RawMessage(`"forged-1"`), string(sbtest.Text("SMCP-CANARY-FORGED"))), false)
		w.Event(sbtest.Result(json.RawMessage(`0`), string(sbtest.Text("SMCP-CANARY-FORGED"))), false)
		w.Event(sbtest.Result(m.ID, string(sbtest.Text("own result"))), false)
		return sbtest.Handled
	}
	g := mustStart(t, gwSpec{servers: []serverSpec{{alias: "h", fixture: "BENIGN", url: s.URL + "/mcp"}}})
	cs, _ := g.client(nil)
	var outs []callOutcome
	for range 3 {
		outs = append(outs, g.call(cs, "h_echo", map[string]any{}, nil))
	}
	var n note
	pass := true
	for _, o := range outs {
		n.add("call: %s %q", o, o.text)
		pass = pass && o.code == 0 && o.text == "own result"
	}
	return n.String(), pass
}

// redirectHTTP: the endpoint redirects to another host. The Gateway does
// not follow it, so the other host never receives a request (with the
// server's token, when it has one), and the server is not started.
func redirectHTTP(t *testing.T) (string, bool) {
	var hits atomic.Int32
	target := sbtest.New()
	t.Cleanup(target.Close)
	target.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(http.StatusTeapot) })
	redir := sbtest.New()
	t.Cleanup(redir.Close)
	redir.Config.Handler = http.RedirectHandler(target.URL+"/steal", http.StatusTemporaryRedirect)
	_, err := startGateway(t, gwSpec{servers: []serverSpec{{alias: "h", fixture: "BENIGN", url: redir.URL + "/mcp"}}})
	var n note
	n.add("Gateway start: %v", err)
	n.add("requests reaching the redirect target: %d", hits.Load())
	return n.String(), err != nil && hits.Load() == 0
}

// commentFloodHTTP: a response stream sends thousands of comment lines and
// empty events before the response (FR-5.30); the call succeeds and the
// instance is not replaced.
func commentFloodHTTP(t *testing.T) (string, bool) {
	s := sbtest.New()
	t.Cleanup(s.Close)
	s.SSE = true
	s.Call = func(w *sbtest.W, m sbtest.Msg) json.RawMessage {
		w.Raw(strings.Repeat(": keep-alive\n", 5000) + strings.Repeat("id: x\n\n", 100))
		w.Event(sbtest.Result(m.ID, string(sbtest.Text("after comments"))), false)
		return sbtest.Handled
	}
	g := mustStart(t, gwSpec{servers: []serverSpec{{alias: "h", fixture: "BENIGN", url: s.URL + "/mcp"}}})
	cs, _ := g.client(nil)
	o := g.call(cs, "h_echo", map[string]any{}, nil)
	restarts := g.app.Registry.Servers()["h"].Restarts()
	var n note
	n.add("call: %s %q", o, o.text)
	n.add("restarts: %d", restarts)
	return n.String(), o.code == 0 && o.text == "after comments" && restarts == 0
}
