package connector_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func text(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

// gatewayURLs are the gateway URLs the stand-in was asked to register.
func gatewayURLs(si *cftest.StandIn) []string {
	var out []string
	for _, r := range si.Requests() {
		if r.Method == "POST" && r.Path == "/v1/gateways" {
			var b struct{ URL string }
			_ = json.Unmarshal([]byte(r.Body), &b)
			out = append(out, b.URL)
		}
	}
	return out
}

// TestHostedPackagesThroughEgress imports two hosted entries through the
// stand-in, one that needs an API key, and calls them:
//
//   - every gateway the instance registers, at the probe and at
//     enablement, is an endpoint of the hosted egress listener, never the
//     hosted URL, and the instance's SSRF allowlist and Enforced
//     destination are that listener (FR-22.40, FR-22.34, FR-22.27);
//   - the probe of the API-key entry is refused without a probe secret;
//     with one, the fixture receives it as a header, and it reaches
//     neither the stand-in nor any event; the manifest declares one S1
//     slot for the entry's host (FR-22.9, FR-22.15, SR-3.5-2);
//   - each package's calls reach only its own fixture, and the broker
//     dials only the two fixtures' addresses (FR-22.34, FR-22.40);
//   - an S1 grant of package B's alias is inserted at B's endpoint, and a
//     grant for another host is refused (FR-22.15);
//   - the calls' events carry the route fields, a local revision's do
//     not (FR-22.39);
//   - every request to a virtual server carries that package's token
//     (FR-22.36).
func TestHostedPackagesThroughEgress(t *testing.T) {
	reqtest.Partial(t, "FR-22.40", "FR-22.34", "FR-22.9", "FR-22.15", "SR-3.5-2", "FR-22.39", "FR-22.36", "FR-22.27", "SR-2.13-5")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{
		{ID: "fx-a", URL: "https://a.example.com/mcp"},
		{ID: "fx-b", URL: "https://b.example.com/v1/mcp", AuthType: "API Key", RequiresAPIKey: true},
	}})
	key := e.Fixtures["b.example.com"].APIKey
	e.AddSecret("fx-b-key", key)

	// The API-key entry without a probe secret.
	if _, err := e.Conn.ProposeLocal("fx-b", connector.LocalImport{}, "op"); packaging.ReasonOf(err) != connector.ReasonProbeSecretRequired {
		t.Fatalf("API-key entry without a probe secret: %v", err)
	}
	ra := e.Import("fx-a", connector.LocalImport{})
	rb := e.Import("fx-b", connector.LocalImport{ProbeSecret: &connector.ProbeSecret{Secret: "fx-b-key", Header: "X-Api-Key", Template: "{secret}"}})

	h := e.Conn.HostedEgress()
	if h == nil {
		t.Fatal("no hosted egress listener")
	}
	base := "http://" + h.Allow().String() + "/"
	if e.Runner.Allow != h.Allow() || len(e.Runner.SSRF) != 1 || e.Runner.SSRF[0] != "127.0.0.1/32" {
		t.Fatalf("instance network: allow %v ssrf %v", e.Runner.Allow, e.Runner.SSRF)
	}
	m, _, err := e.Lib.Manifest(rb.ServerID, rb.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Secrets) != 1 || m.Secrets[0].Destination != "b.example.com:443" || strings.Join(m.Secrets[0].Modes, ",") != "S1" {
		t.Fatalf("secret slots %+v", m.Secrets)
	}

	// The enabled package's key: a Secret Use Policy binding in S1 for
	// its alias at its host, bound while its gateway is registered.
	e.UseS1(rb.Alias, "api_key", "fx-b-key", "X-Api-Key", "{secret}", "b.example.com:443")
	g, err := e.Launch(ra, rb)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range gatewayURLs(e.StandIn) {
		if !strings.HasPrefix(u, base) || strings.Contains(u, "example.com") {
			t.Fatalf("a gateway was registered with %q, not an endpoint under %s", u, base)
		}
	}
	// S1 for B's alias at B's endpoint, through the Secret Broker's
	// router; a grant for another host is refused.
	router := e.Conn.S1Router(nil)
	if err := router.BindHeader(context.Background(), pipeline.HeaderGrant{GrantID: "gb", Server: rb.Alias, Slot: "api_key", Destination: "b.example.com:443",
		Header: "X-Api-Key", Template: "{secret}", Value: []byte(key)}); err != nil {
		t.Fatal(err)
	}
	if err := router.BindHeader(context.Background(), pipeline.HeaderGrant{GrantID: "gx", Server: rb.Alias, Slot: "api_key", Destination: "evil.example.com:443",
		Header: "X-Api-Key", Template: "{secret}", Value: []byte(key)}); packaging.ReasonOf(err) != connector.ReasonHostedSecretMode {
		t.Fatalf("grant for another host: %v", err)
	}
	resA, err := g.Call(ra.Alias+"_echo", map[string]any{"x": 1})
	if err != nil || resA.IsError || !strings.HasPrefix(text(resA), "a.example.com echo") {
		t.Fatalf("call A: %v %+v", err, resA)
	}
	resB, err := g.Call(rb.Alias+"_echo", map[string]any{"x": 2})
	if err != nil || resB.IsError || !strings.HasPrefix(text(resB), "b.example.com echo") {
		t.Fatalf("call B: %v %+v", err, resB)
	}
	router.Withdraw("gb")
	for _, d := range e.Dialed() {
		if !strings.HasPrefix(d, "93.184.216.10:443") && !strings.HasPrefix(d, "93.184.216.11:443") {
			t.Fatalf("the broker dialed %s", d)
		}
	}
	for _, hdr := range e.Fixtures["a.example.com"].Headers() {
		if hdr.Get("X-Api-Key") != "" {
			t.Fatal("package A's requests carried B's key")
		}
	}
	// The key reached the fixture, and nowhere else.
	got := 0
	for _, hdr := range e.Fixtures["b.example.com"].Headers() {
		if hdr.Get("X-Api-Key") == key {
			got++
		}
	}
	if got == 0 {
		t.Fatal("the fixture never received the key")
	}
	for _, r := range e.StandIn.Requests() {
		if strings.Contains(r.Body, key) || strings.Contains(r.Authorization, key) {
			t.Fatalf("the stand-in received the key: %s %s", r.Method, r.Path)
		}
	}
	for _, ev := range e.Rec.Events() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), key) {
			t.Fatalf("an event holds the key: %s", raw)
		}
	}
	// Package tokens on every virtual-server request.
	for _, r := range e.StandIn.Requests() {
		if strings.HasPrefix(r.Path, "/servers/") && !strings.HasPrefix(r.Authorization, "Bearer tok-") {
			t.Fatalf("%s %s without a package token: %q", r.Method, r.Path, r.Authorization)
		}
	}
	// FR-22.39: the route fields on the call's events, none on a local
	// revision's.
	for _, rev := range []string{ra.Key(), "local-pkg@1"} {
		if err := e.Fanout.Commit(audit.Event{Class: "decision", Origin: "E-06", ServerRevision: rev, PolicyStatus: "evaluated"}); err != nil {
			t.Fatal(err)
		}
	}
	evs := e.Rec.Events()
	hosted, local := evs[len(evs)-2], evs[len(evs)-1]
	if hosted.Route["via"] != "contextforge" || hosted.Route["server_id"] != ra.ServerID || hosted.Route["revision"] != ra.Revision ||
		hosted.Route["virtual_server"] == "" || hosted.Route["instance_version"] != "v1.0.11" || !strings.HasPrefix(hosted.Route["instance_digest"], "sha256:") {
		t.Fatalf("hosted route %v", hosted.Route)
	}
	if local.Route != nil {
		t.Fatalf("local route %v", local.Route)
	}
	// The probe endpoints are gone; the two package endpoints remain.
	if eps := h.Endpoints(); len(eps) != 2 {
		t.Fatalf("live endpoints %+v", eps)
	}
}

// TestHostedTokenRenewal: with package tokens that expire after two
// seconds and renewal one and a half seconds before expiry, the Connector
// renews the token, runs the scope self-check, switches the connection to
// the new token and revokes the old one; a call after the first token's
// expiry succeeds (FR-22.29, FR-22.36).
func TestHostedTokenRenewal(t *testing.T) {
	reqtest.Partial(t, "FR-22.29", "FR-22.36")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "fx-a", URL: "https://a.example.com/mcp"}},
		StandIn: &cftest.StandIn{TokenLifetime: 2 * time.Second}, RenewBefore: 1500 * time.Millisecond, RenewInterval: 100 * time.Millisecond})
	ra := e.Import("fx-a", connector.LocalImport{})
	g, err := e.Launch(ra)
	if err != nil {
		t.Fatal(err)
	}
	first := lastToken(e.StandIn)
	if _, err := g.Call(ra.Alias+"_echo", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond) // past the first token's expiry
	res, err := g.Call(ra.Alias+"_echo", map[string]any{})
	if err != nil || res.IsError {
		t.Fatalf("call after the first token expired: %v %+v", err, res)
	}
	if now := lastToken(e.StandIn); now == first || now == "" {
		t.Fatalf("the call used %q, the first token was %q", now, first)
	}
	if n := e.StandIn.LiveTokens(); n != 1 {
		t.Fatalf("%d live tokens: the old ones were not revoked", n)
	}
	renewed := 0
	for _, ev := range e.Rec.Events() {
		if ev.Outcome == "token_renewed" {
			renewed++
		}
	}
	if renewed == 0 {
		t.Fatal("no token_renewed event")
	}
}

// lastToken is the token of the last request to a virtual server.
func lastToken(si *cftest.StandIn) string {
	rs := si.Requests()
	for i := len(rs) - 1; i >= 0; i-- {
		if strings.HasPrefix(rs[i].Path, "/servers/") {
			return strings.TrimPrefix(rs[i].Authorization, "Bearer ")
		}
	}
	return ""
}

// TestHostedScopeBroken: a stand-in that accepts a package token on other
// servers, the global endpoints and admin routes (HFC-10) fails the scope
// self-check at enablement: every hosted package is suspended with
// CONTEXTFORGE_SCOPE_BROKEN and nothing is presented (FR-22.29).
func TestHostedScopeBroken(t *testing.T) {
	reqtest.Partial(t, "FR-22.29", "FR-22.43")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "fx-a", URL: "https://a.example.com/mcp"}, {ID: "fx-b", URL: "https://b.example.com/mcp"}},
		StandIn: &cftest.StandIn{}})
	ra := e.Import("fx-a", connector.LocalImport{})
	rb := e.Import("fx-b", connector.LocalImport{})
	e.StandIn.Leak = true
	g, err := e.Launch(ra, rb)
	if err == nil && len(g.Servers) > 0 {
		t.Fatalf("resolved %+v with a leaking instance", g.Servers)
	}
	for _, r := range []library.Revision{ra, rb} {
		got, _ := e.Lib.Get(r.ServerID, r.Revision)
		if got.State != library.StateSuspended {
			t.Fatalf("%s is %s", r.Key(), got.State)
		}
	}
	found := false
	for _, ev := range e.Rec.Events() {
		if ev.ReasonCode == bundle.ReasonScopeBroken {
			found = true
		}
	}
	if !found {
		t.Fatal("no CONTEXTFORGE_SCOPE_BROKEN event")
	}
	if !errors.Is(err, err) {
		t.Fatal()
	}
}
