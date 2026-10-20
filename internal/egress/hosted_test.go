package egress

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// hostedHarness is a hosted set whose resolver gives the fixture hosts
// public addresses and whose dialer connects every validated address to
// the TLS fixture on loopback, recording what was dialed.
type hostedHarness struct {
	h      *Hosted
	ev     *audit.Memory
	res    *fakeResolver
	mu     sync.Mutex
	dialed []string
}

func newHostedHarness(t *testing.T, fixture *httptest.Server) *hostedHarness {
	t.Helper()
	hh := &hostedHarness{ev: &audit.Memory{}, res: &fakeResolver{answers: map[string][][]string{}}}
	pool := x509.NewCertPool()
	pool.AddCert(fixture.Certificate())
	fx := fixture.Listener.Addr().String()
	d := &net.Dialer{Timeout: 2 * time.Second}
	o := Options{Evidence: hh.ev, Resolver: hh.res, RootCAs: pool, Recent: 100,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			hh.mu.Lock()
			hh.dialed = append(hh.dialed, addr)
			hh.mu.Unlock()
			return d.DialContext(ctx, network, fx)
		}}
	h, err := NewHosted(o, netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	hh.h = h
	return hh
}

func (hh *hostedHarness) dials() []string {
	hh.mu.Lock()
	defer hh.mu.Unlock()
	return append([]string(nil), hh.dialed...)
}

// TestHostedEndpoints: each hosted package gets its own endpoint on the
// one hosted listener, bound to its host and port 443 with the broker
// originating TLS; a request on a removed or unknown key, a redirect to
// another host or to a private address, and a host that resolves to a
// private or metadata address are refused and recorded; an S1 header
// grant of the endpoint's server reaches the destination and the instance
// never holds it (FR-22.40, FR-22.15, SR-3.5-2).
func TestHostedEndpoints(t *testing.T) {
	reqtest.Partial(t, "FR-22.40", "FR-22.15", "SR-3.5-2", "FR-22.9")
	var mu sync.Mutex
	var seen []string
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host+" "+r.Method+" "+r.URL.RequestURI()+" key="+r.Header.Get("X-Api-Key"))
		mu.Unlock()
		switch r.URL.Path {
		case "/redirect-other":
			http.Redirect(w, r, "https://other.example.com/x", http.StatusFound)
		case "/redirect-private":
			http.Redirect(w, r, "https://10.0.0.1/x", http.StatusFound)
		default:
			_, _ = io.WriteString(w, "ok "+r.URL.RequestURI())
		}
	}))
	defer fixture.Close()
	hh := newHostedHarness(t, fixture)
	hh.res.answers["mcp.example.com"] = [][]string{{"93.184.216.34"}}
	hh.res.answers["other.example.com"] = [][]string{{"93.184.216.35"}}
	hh.res.answers["private.example.com"] = [][]string{{"10.0.0.1"}}

	a, err := hh.h.Add("pkg-a", "MCP.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hh.h.Add("pkg-b", "mcp.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.Base == b.Base || !strings.HasPrefix(a.Base, "http://"+hh.h.Allow().String()+"/") {
		t.Fatalf("endpoints %q %q on %s", a.Base, b.Base, hh.h.Allow())
	}
	u, err := a.URL("https://mcp.example.com/v1/mcp?x=1")
	if err != nil || u != a.Base+"/v1/mcp?x=1" {
		t.Fatalf("endpoint URL %q %v", u, err)
	}
	// S1 for pkg-a only: the header is inserted on pkg-a's requests.
	secret := "sk-hosted-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := hh.h.Broker().BindHeader(context.Background(), pipeline.HeaderGrant{GrantID: "g", Server: "pkg-a", Slot: "api_key",
		Destination: "mcp.example.com:443", Header: "X-Api-Key", Template: "{secret}", Value: []byte(secret)}); err != nil {
		t.Fatal(err)
	}
	get := func(raw string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, raw, strings.NewReader("{}"))
		req.Header.Set("X-Api-Key", "instance-supplied")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(body)
	}
	if resp, body := get(u); resp.StatusCode != 200 || body != "ok /v1/mcp?x=1" {
		t.Fatalf("endpoint a: %d %q", resp.StatusCode, body)
	}
	ub, _ := b.URL("https://mcp.example.com/v1/mcp")
	if resp, _ := get(ub); resp.StatusCode != 200 {
		t.Fatalf("endpoint b: %d", resp.StatusCode)
	}
	mu.Lock()
	got := strings.Join(seen, "\n")
	mu.Unlock()
	// pkg-a's header replaces what the instance sent; pkg-b has no grant
	// and never gets pkg-a's secret.
	if !strings.Contains(got, "mcp.example.com POST /v1/mcp?x=1 key="+secret+"\n") || !strings.HasSuffix(got, "mcp.example.com POST /v1/mcp key=instance-supplied") {
		t.Fatalf("fixture saw:\n%s", got)
	}
	for _, d := range hh.dials() {
		if !strings.HasPrefix(d, "93.184.216.34:443") {
			t.Fatalf("dialed %s", d)
		}
	}

	// Refusals: unknown key, redirects off the endpoint's host, and a
	// destination that resolves to a private address.
	for _, c := range []struct {
		url, reason string
	}{
		{"http://" + hh.h.Allow().String() + "/0123456789abcdef0123456789abcdef/v1/mcp", ReasonNoGrant},
		{a.Base + "/redirect-other", ReasonRedirect},
		{a.Base + "/redirect-private", ReasonRedirect},
	} {
		req, _ := http.NewRequest(http.MethodGet, c.url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if reasonOf(resp) != c.reason {
			t.Fatalf("%s: %d %s, want %s", c.url, resp.StatusCode, reasonOf(resp), c.reason)
		}
	}
	p, err := hh.h.Add("probe-x", "private.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	m, err := hh.h.Add("probe-meta", "169.254.169.254", 443)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []HostedEndpoint{p, m} {
		resp, err := http.Get(e.Base + "/sse")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if reasonOf(resp) != ReasonAddressRefused {
			t.Fatalf("%s: %d %s", e.Host, resp.StatusCode, reasonOf(resp))
		}
	}
	// A removed endpoint is refused.
	hh.h.Remove(a)
	if resp, _ := get(u); reasonOf(resp) != ReasonNoGrant {
		t.Fatalf("removed endpoint: %d %s", resp.StatusCode, reasonOf(resp))
	}
	// Evidence: every operation names its endpoint's server, never the key.
	key := strings.TrimPrefix(a.Base, "http://"+hh.h.Allow().String()+"/")
	denied := 0
	for _, ev := range hh.ev.Events() {
		raw := fmt.Sprint(ev.Detail)
		if strings.Contains(raw, key) || strings.Contains(raw, secret) {
			t.Fatalf("event holds the key or the secret: %+v", ev)
		}
		if ev.Phase == audit.PhaseDenied {
			denied++
		}
	}
	if denied < 5 {
		t.Fatalf("%d denied events", denied)
	}
	if n := len(hh.h.Endpoints()); n != 3 {
		t.Fatalf("%d live endpoints", n)
	}
}

// TestHostedSSEEndpointRewrite: the legacy SSE transport's "endpoint"
// event is rewritten so that the instance posts its messages through the
// same endpoint, a URL on another host is replaced by a path no endpoint
// serves, and each event is flushed as it arrives.
func TestHostedSSEEndpointRewrite(t *testing.T) {
	reqtest.Partial(t, "FR-22.40")
	release := make(chan struct{})
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: endpoint\ndata: /messages?session=1\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, ": comment\nevent: endpoint\ndata: https://evil.example/messages\n\nevent: message\ndata: {\"x\":1}\n\n")
	}))
	defer fixture.Close()
	hh := newHostedHarness(t, fixture)
	hh.res.answers["mcp.example.com"] = [][]string{{"93.184.216.34"}}
	e, err := hh.h.Add("pkg", "mcp.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(e.Base + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	prefix := strings.TrimPrefix(e.Base, "http://"+hh.h.Allow().String())
	buf := make([]byte, 256)
	n, err := io.ReadAtLeast(resp.Body, buf, len("event: endpoint\ndata: "+prefix+"/messages?session=1\n\n"))
	if err != nil {
		t.Fatalf("first event not flushed: %v", err)
	}
	if got := string(buf[:n]); got != "event: endpoint\ndata: "+prefix+"/messages?session=1\n\n" {
		t.Fatalf("first event %q", got)
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if want := ": comment\nevent: endpoint\ndata: " + prefix + "/foreign-endpoint\n\nevent: message\ndata: {\"x\":1}\n\n"; string(rest) != want {
		t.Fatalf("rest %q", rest)
	}
	for v, want := range map[string]string{
		"https://mcp.example.com/m?s=2":     "/k/m?s=2",
		"https://mcp.example.com:8443/m":    "/k/foreign-endpoint",
		"http://mcp.example.com/m":          "/k/foreign-endpoint",
		"messages":                          "/k/messages",
		"https://OTHER.example.com/m":       "/k/foreign-endpoint",
		"https://mcp.example.com:443/a%2Fb": "/k/a%2Fb",
	} {
		if got := endpointPath(v, "mcp.example.com", 443, "/k"); got != want {
			t.Errorf("endpointPath(%q) = %q, want %q", v, got, want)
		}
	}
}
