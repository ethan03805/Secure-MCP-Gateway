package versions

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type nopCtl struct{}

func (nopCtl) Health() edge.Health                                   { return edge.Health{State: "healthy"} }
func (nopCtl) Stop(string, string) error                             { return nil }
func (nopCtl) Resume(string) error                                   { return nil }
func (nopCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

// roleTokens authenticates "role-<role>" as an actor of that role, as the
// console's account sessions do.
type roleTokens struct{}

func (roleTokens) Authenticate(tok string) (string, string, bool) {
	role, ok := strings.CutPrefix(tok, "role-")
	if !ok {
		return "", "", false
	}
	return role + ":tester", role, true
}

type fixture struct {
	t       *testing.T
	srv     *httptest.Server
	token   string
	journal string
	snaps   *baseline.SnapshotStore
	svc     *Service
}

func newFixture(t *testing.T) (*fixture, *audit.Fanout) {
	t.Helper()
	state := t.TempDir()
	if err := keys.Ensure(state); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jdir := filepath.Join(state, "journal")
	j, err := audit.Open(jdir, key, audit.Options{MaxEvents: 4, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.NewFanout(j, diag.Discard())
	t.Cleanup(func() { ev.Close(); _ = j.Close() })
	srv := httptest.NewUnstartedServer(nil)
	cfg, err := config.Parse([]byte(fmt.Sprintf("[admin_listener]\naddress = %q\n[state]\ndir = %q\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g\"\n",
		srv.Listener.Addr().String(), state)))
	if err != nil {
		t.Fatal(err)
	}
	api, err := adminapi.New(adminapi.Options{Config: cfg, Controller: nopCtl{}, Evidence: ev})
	if err != nil {
		t.Fatal(err)
	}
	api.AddAuthenticator(roleTokens{})
	snaps, err := baseline.OpenSnapshotStore(filepath.Join(state, "baselines"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{JournalDir: jdir, Evidence: ev}
	svc.SetPurger(KindBaselineSnapshot, BaselinePurger(snaps))
	svc.Register(api)
	srv.Config.Handler = api.Handler()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tok, err := keys.LoadAdminToken(state)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, srv: srv, token: tok, journal: jdir, snaps: snaps, svc: svc}, ev
}

func (f *fixture) purge(token, kind, version string) (int, map[string]any) {
	f.t.Helper()
	b, _ := json.Marshal(map[string]string{"kind": kind, "version": version})
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/versions/purge", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (f *fixture) snapshot() string {
	f.t.Helper()
	s := &baseline.Snapshot{ID: ids.New(), CreatedAt: time.Now().UTC(), Trigger: "operator"}
	d, err := s.ComputeDigest()
	if err != nil {
		f.t.Fatal(err)
	}
	s.Digest = d
	if err := f.snaps.Save(s); err != nil {
		f.t.Fatal(err)
	}
	return s.ID
}

func (f *fixture) exists(id string) bool {
	_, err := f.snaps.Load(id)
	return err == nil
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func journalReasons(t *testing.T, dir string) map[string]int {
	t.Helper()
	evs, err := audit.ReadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, ev := range evs {
		if ev.Origin == "E-28" {
			out[ev.ReasonCode]++
		}
	}
	return out
}

// TestReferencedVersionsAreRetained is SR-6.14-1: for every version kind
// (rule, route, policy revision, server revision, tool revision, profile,
// baseline snapshot) an attempt to purge a version that an unexpired audit
// record references is refused with VERSION_REFERENCED, recorded, and
// changes nothing; an unreferenced baseline snapshot is purged after its
// receipt is journaled. The purge is the Appendix C "Purge" row: every
// role but the Administrator is refused.
func TestReferencedVersionsAreRetained(t *testing.T) {
	reqtest.Verifies(t, "SR-6.14-1")
	f, ev := newFixture(t)
	refSnap, freeSnap, roleSnap := f.snapshot(), f.snapshot(), f.snapshot()
	commit := func(e audit.Event) {
		t.Helper()
		e.PolicyStatus = "evaluated"
		if err := ev.Commit(e); err != nil {
			t.Fatal(err)
		}
	}
	// The audit records as the elements write them.
	commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "activated", PolicyRevision: "pr-7"})
	commit(audit.Event{Class: "decision", Origin: "E-06", Phase: audit.PhaseAuthorized, Outcome: "permit", CorrelationID: "c1", DecisionID: "d1",
		PolicyRevision: "pr-7", ServerRevision: "live-abc", ToolRevision: "live-abc/echo",
		Detail: map[string]any{"considered_rules": []any{"pr-7/dev/allow-echo", "pr-7/dev/deny-write"}, "decisive_rules": []any{"pr-7/dev/allow-echo"},
			"route": "route-fs@3", "obligations": map[string]any{"audit_profile": "audit_profile@2"}}})
	commit(audit.Event{Class: "baseline", Origin: "E-30", Outcome: "snapshot_built", Detail: map[string]any{"snapshot_id": refSnap}})
	commit(audit.Event{Class: "anomaly", Origin: "E-31", CorrelationID: "c1", Outcome: "elevated", Detail: map[string]any{"snapshot_id": refSnap}})

	referenced := []struct{ kind, version string }{
		{KindRule, "pr-7/dev/deny-write"}, // considered, not decisive
		{KindRoute, "route-fs@3"},
		{KindPolicy, "pr-7"},
		{KindServer, "live-abc"},
		{KindTool, "live-abc/echo"},
		{KindProfile, "audit_profile@2"},
		{KindBaselineSnapshot, refSnap},
	}
	for _, r := range referenced {
		st, out := f.purge(f.token, r.kind, r.version)
		if st != http.StatusConflict || errCode(out) != ReasonReferenced {
			t.Errorf("%s %s: %d %v", r.kind, r.version, st, out)
			continue
		}
		if refs, _ := out["references"].(map[string]any); refs["count"].(float64) < 1 || refs["first_event_id"] == "" {
			t.Errorf("%s %s: references %v", r.kind, r.version, out["references"])
		}
	}
	if !f.exists(refSnap) {
		t.Fatal("a referenced baseline snapshot was deleted")
	}
	if n := journalReasons(t, f.journal)[ReasonReferenced]; n != len(referenced) {
		t.Fatalf("%d refusals recorded, want %d", n, len(referenced))
	}

	// Every role but the Administrator is refused; unauthenticated callers too.
	for _, role := range adminapi.Roles {
		if role == adminapi.RoleAdministrator {
			continue
		}
		if st, out := f.purge("role-"+role, KindBaselineSnapshot, roleSnap); st != http.StatusForbidden {
			t.Errorf("%s: %d %v", role, st, out)
		}
	}
	for _, tok := range []string{"", "not-a-token"} {
		if st, _ := f.purge(tok, KindBaselineSnapshot, roleSnap); st != http.StatusUnauthorized {
			t.Errorf("token %q: %d", tok, st)
		}
	}
	if !f.exists(roleSnap) {
		t.Fatal("a refused caller deleted a snapshot")
	}

	// An unreferenced snapshot is purged; the receipt comes first.
	if st, out := f.purge(f.token, KindBaselineSnapshot, freeSnap); st != http.StatusOK || out["purged"] != true {
		t.Fatalf("unreferenced snapshot: %d %v", st, out)
	}
	if f.exists(freeSnap) {
		t.Fatal("purged snapshot still stored")
	}
	if st, out := f.purge("role-"+adminapi.RoleAdministrator, KindBaselineSnapshot, roleSnap); st != http.StatusOK {
		t.Fatalf("administrator account: %d %v", st, out)
	}
	if st, out := f.purge(f.token, KindBaselineSnapshot, freeSnap); st != http.StatusNotFound {
		t.Fatalf("second purge: %d %v", st, out)
	}
	if r := journalReasons(t, f.journal); r[ReasonPurged] != 2 || r[ReasonPurgeFailed] != 0 {
		t.Fatalf("receipts %v", r)
	}
	// A kind without a deletion is retained; the refusal does not make the
	// version referenced.
	if st, out := f.purge(f.token, KindRule, "pr-9/dev/unused"); st != http.StatusConflict || errCode(out) != ReasonRetained {
		t.Fatalf("unreferenced rule: %d %v", st, out)
	}
	if ref, err := f.svc.References("pr-9/dev/unused"); err != nil || ref.Count != 0 {
		t.Fatalf("refusal counted as a reference: %+v %v", ref, err)
	}
	// Bad requests.
	if st, _ := f.purge(f.token, "nonsense", "x"); st != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d", st)
	}
	if st, _ := f.purge(f.token, KindRule, " "); st != http.StatusBadRequest {
		t.Fatalf("empty version: %d", st)
	}
}

// TestReferenceMatching: a value names a version when it is the version
// or a path below it; prefixes of other IDs do not count.
func TestReferenceMatching(t *testing.T) {
	reqtest.Partial(t, "SR-6.14-1")
	cases := []struct {
		value, id string
		want      bool
	}{
		{"pr-7", "pr-7", true}, {"pr-7/dev/allow", "pr-7", true}, {"pr-70", "pr-7", false}, {"pr-7x/dev", "pr-7", false},
		{"live-abc/echo", "live-abc/echo", true}, {"live-abc/echo2", "live-abc/echo", false},
	}
	for _, c := range cases {
		if got := references(c.value, c.id); got != c.want {
			t.Errorf("references(%q, %q) = %v", c.value, c.id, got)
		}
	}
	ev := audit.Event{Detail: map[string]any{"a": []any{map[string]any{"b": "snap-1"}}}}
	if !eventRefers(ev, "snap-1") || eventRefers(ev, "snap") {
		t.Fatal("nested detail")
	}
	own := audit.Event{Origin: "E-28", ReasonCode: ReasonPurged, Detail: map[string]any{"version": "snap-1"}}
	if eventRefers(own, "snap-1") {
		t.Fatal("a purge receipt counted as a reference")
	}
}
