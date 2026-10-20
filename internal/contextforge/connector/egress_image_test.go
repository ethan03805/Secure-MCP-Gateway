package connector_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// adminOf is an administrator client of the harness's running instance.
func adminOf(t *testing.T, e *cfharness.Env) *bundle.Admin {
	t.Helper()
	port := e.Conn.Instance().Port
	if port == 0 {
		t.Fatal("the instance is not running")
	}
	return &bundle.Admin{Base: "http://127.0.0.1:" + strconv.Itoa(port), AdminToken: func() (string, error) {
		names := make([]string, 0, len(bundle.CredentialKeys))
		for _, k := range bundle.CredentialKeys {
			names = append(names, strings.ReplaceAll(strings.ToLower(k), "_", "-"))
		}
		vals, err := e.Broker.DeliverComponent("contextforge", names)
		if err != nil {
			return "", err
		}
		creds := bundle.Credentials{}
		for _, k := range bundle.CredentialKeys {
			creds[k] = string(vals[strings.ReplaceAll(strings.ToLower(k), "_", "-")])
		}
		return bundle.AdminToken(creds, time.Now(), 5*time.Minute)
	}}
}

// instanceContainer is the container that publishes the instance's port.
func instanceContainer(t *testing.T, eng string, e *cfharness.Env) string {
	t.Helper()
	out, err := exec.Command(eng, "ps", "--filter", "publish="+strconv.Itoa(e.Conn.Instance().Port), "--format", "{{.ID}}").Output()
	id := strings.TrimSpace(string(out))
	if err != nil || id == "" || strings.Contains(id, "\n") {
		t.Fatalf("the instance's container: %q %v", id, err)
	}
	return id
}

// secretInContainer reports whether the value appears in the container's
// configured environment or in any file under /app/data (D-16, its
// database) or /tmp. It never prints the value.
func secretInContainer(t *testing.T, eng, ctr, value string) []string {
	t.Helper()
	var where []string
	if out, err := exec.Command(eng, "inspect", "--format", "{{json .Config.Env}}", ctr).Output(); err != nil || bytes.Contains(out, []byte(value)) {
		where = append(where, "environment")
	}
	script := "import os,sys\nv=sys.stdin.buffer.read()\nfor root in ('/app/data','/tmp'):\n  for d,_,fs in os.walk(root):\n    for f in fs:\n      p=os.path.join(d,f)\n      try:\n        if v in open(p,'rb').read(): print(p)\n      except OSError: pass\n"
	cmd := exec.Command(eng, "exec", "-i", ctr, "python3", "-c", script)
	cmd.Stdin = strings.NewReader(value)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("searching the instance's files: %v", err)
	}
	where = append(where, strings.Fields(string(out))...)
	return where
}

// TestHostedEgressImage runs hosted packages through the pinned image and
// the hosted egress listener of a real Egress Broker (SMCP_CONTEXTFORGE_IMAGE=1,
// Docker, cosign), with three HTTPS fixture hosts:
//
//   - FR-22.9: the probe of an entry that requires an API key, with a
//     probe secret, and of one that does not, reads each tool list; while
//     a third fixture host is reachable, every connection the broker makes
//     for the instance during each probe goes to that entry's host only;
//     the probe secret reaches its fixture as a header and is in neither
//     the instance's environment nor any file of its data volume or
//     database;
//   - FR-22.34: with both packages enabled, the instance holds two teams,
//     two non-admin users, two gateways (each named as its manifest says,
//     with the package's own egress endpoint as its URL) and two virtual
//     servers, each object of a package in its team with team visibility,
//     each virtual server listing only its package's tools, and each
//     package's calls reach only its fixture, through the virtual-server
//     endpoint of its package.
func TestHostedEgressImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge image")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not installed")
	}
	e := cfharness.New(t, cfharness.Options{Image: true, Engine: docker, Entries: []cfharness.Entry{
		{ID: "eg-open", URL: "https://eg-open.example.com/mcp"},
		{ID: "eg-key", URL: "https://eg-key.example.com/mcp", AuthType: "API Key", RequiresAPIKey: true},
		{ID: "eg-other", URL: "https://eg-other.example.com/mcp"},
	}})
	key := e.Fixtures["eg-key.example.com"].APIKey
	e.AddSecret("eg-key-secret", key)
	probe := func(id string, in connector.LocalImport) (connector.ProposalView, []string) {
		t.Helper()
		before := len(e.Dialed())
		p, err := e.Probe(id, in)
		if err != nil || p.State != "ready" {
			t.Fatalf("probe %s: %v %s %s", id, err, p.ReasonCode, p.Error)
		}
		return p, e.Dialed()[before:]
	}
	pk, dk := probe("eg-key", connector.LocalImport{ProbeSecret: &connector.ProbeSecret{Secret: "eg-key-secret", Header: "X-Api-Key", Template: "{secret}"}})
	po, do := probe("eg-open", connector.LocalImport{})
	if len(pk.Decision.Fields.Tools) != 2 || len(po.Decision.Fields.Tools) != 2 {
		t.Fatalf("tool lists %v %v", pk.Decision.Fields.Tools, po.Decision.Fields.Tools)
	}
	for name, dials := range map[string][]string{"eg-key": dk, "eg-open": do} {
		if len(dials) == 0 {
			t.Fatalf("the probe of %s made no connection", name)
		}
		for _, d := range dials {
			if d != dials[0] {
				t.Fatalf("the probe of %s reached %s and %s", name, dials[0], d)
			}
		}
	}
	if dk[0] == do[0] {
		t.Fatal("both probes reached the same address")
	}
	if n := len(e.Fixtures["eg-other.example.com"].Headers()); n != 0 {
		t.Fatalf("the third fixture host received %d requests", n)
	}
	got := false
	for _, h := range e.Fixtures["eg-key.example.com"].Headers() {
		if h.Get("X-Api-Key") == key {
			got = true
		}
	}
	if !got {
		t.Fatal("the probe secret did not reach its fixture")
	}
	ctx := context.Background()
	if err := e.Conn.StartInstance(ctx, "op"); err != nil { // the probe's start may have ended
		t.Fatal(err)
	}
	ctr := instanceContainer(t, docker, e)
	if where := secretInContainer(t, docker, ctr, key); len(where) > 0 {
		t.Fatalf("the probe secret is in the instance's %v", where)
	}
	reqtest.Verifies(t, "FR-22.9")

	// FR-22.34: both packages enabled and called.
	decide := func(p connector.ProposalView) {
		t.Helper()
		if _, err := e.Conn.Decide(p.ID, true, p.Decision.SHA256, "op"); err != nil {
			t.Fatal(err)
		}
	}
	decide(pk)
	decide(po)
	var revs = map[string]string{}
	for _, r := range e.Lib.Revisions() {
		revs[r.ServerID] = r.Revision
	}
	enable := func(id string) (alias string) {
		t.Helper()
		r, err := e.Lib.Enable(id, revs[id], library.EnableOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return r.Alias
	}
	ka, oa := enable("eg-key"), enable("eg-open")
	e.UseS1(ka, "api_key", "eg-key-secret", "X-Api-Key", "{secret}", "eg-key.example.com:443")
	kr, _ := e.Lib.Get("eg-key", revs["eg-key"])
	or, _ := e.Lib.Get("eg-open", revs["eg-open"])
	g, err := e.Launch(kr, or)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range g.Servers {
		if !strings.Contains(s.URL, "/servers/") || !strings.HasSuffix(s.URL, "/mcp") {
			t.Fatalf("server %s reached at %s, not its virtual server", s.Alias, s.URL)
		}
	}
	beforeKey, beforeOpen := len(e.Fixtures["eg-key.example.com"].Headers()), len(e.Fixtures["eg-open.example.com"].Headers())
	if res, err := g.Call(ka+"_echo", map[string]any{"x": 1}); err != nil || res.IsError || !strings.Contains(text(res), "eg-key.example.com echo") {
		t.Fatalf("call to the API-key package: %v %+v", err, res)
	}
	if n := len(e.Fixtures["eg-open.example.com"].Headers()); n != beforeOpen {
		t.Fatal("a call of the API-key package reached the other fixture")
	}
	if res, err := g.Call(oa+"_echo", map[string]any{"x": 2}); err != nil || res.IsError || !strings.Contains(text(res), "eg-open.example.com echo") {
		t.Fatalf("call to the open package: %v %+v", err, res)
	}
	if len(e.Fixtures["eg-key.example.com"].Headers()) == beforeKey {
		t.Fatal("the API-key package's call did not reach its fixture")
	}
	a := adminOf(t, e)
	list := func(path string) []bundle.AdminObject {
		t.Helper()
		objs, err := a.List(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		return objs
	}
	gws, servers := list("/v1/gateways?include_inactive=true"), list("/v1/servers?include_inactive=true")
	var teams, users []bundle.AdminObject
	for _, tm := range list("/v1/teams?include_personal=false") {
		if !tm.IsPersonal {
			teams = append(teams, tm)
		}
	}
	for _, u := range list("/v1/auth/email/admin/users") {
		if !u.IsAdmin {
			users = append(users, u)
		}
	}
	if len(gws) != 2 || len(servers) != 2 || len(teams) != 2 || len(users) != 2 {
		t.Fatalf("%d gateways, %d virtual servers, %d teams, %d non-admin users; want 2 each", len(gws), len(servers), len(teams), len(users))
	}
	listener := e.Conn.HostedEgress().Allow().String()
	gwTeam := map[string]string{}
	for _, gw := range gws {
		if !strings.HasPrefix(gw.Name, "smcp-eg-") || gw.Visibility != "team" || gw.TeamID == "" || !strings.Contains(gw.URL, listener) {
			t.Fatalf("gateway %+v (listener %s)", gw, listener)
		}
		gwTeam[gw.ID] = gw.TeamID
	}
	tools, err := a.Tools(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	toolTeam := map[string]string{}
	for _, tl := range tools {
		if tl.Visibility != "team" || tl.TeamID == "" || tl.TeamID != gwTeam[tl.GatewayID] {
			t.Fatalf("tool %+v outside its gateway's team", tl)
		}
		toolTeam[tl.ID] = tl.TeamID
	}
	for _, s := range servers {
		if s.Visibility != "team" || s.TeamID == "" || len(s.AssociatedTools) == 0 {
			t.Fatalf("virtual server %+v", s)
		}
		for _, id := range s.AssociatedTools {
			if toolTeam[id] != s.TeamID {
				t.Fatalf("virtual server %s holds tool %s of another team", s.Name, id)
			}
		}
	}
	reqtest.Verifies(t, "FR-22.34")

	// FR-22.15 (part): after the API-key package's calls, the key is in
	// neither the instance's environment, files and database nor the
	// memory of its processes (read as root on Linux).
	if where := secretInContainer(t, docker, ctr, key); len(where) > 0 {
		t.Fatalf("the API key is in the instance's %v", where)
	}
	if found, checked := secretInMemory(t, docker, ctr, key); checked {
		if found != "" {
			t.Fatalf("the API key is in the memory of the instance's process %s", found)
		}
		reqtest.Partial(t, "FR-22.15")
	}
}
