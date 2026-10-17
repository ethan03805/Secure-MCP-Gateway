package library

import (
	"net/http"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestTrustAnchorRoutes(t *testing.T) {
	// FR-8.18 also covers the G-10 view (console/e2e) and attestations.
	reqtest.Partial(t, "FR-8.18", "FR-14.8")
	r := newRuntime(t, fixtureDesc)
	f := newAPI(t, r)
	k := pkgtest.NewKey(t)
	st, out := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "team", "public_key": string(k.Public), "classes": []string{"low"}, "expires": "2099-01-01"})
	if st != http.StatusCreated || out["key_id"] != k.ID || out["name"] != "team" {
		t.Fatalf("enroll: %d %v", st, out)
	}
	a, err := packaging.LoadAnchors(r.state)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range a.Anchors {
		if x.Name == "team" && x.AddedBy == "operator-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("anchor not saved: %+v", a.Anchors)
	}
	if !r.hasEvent("TRUST_ANCHOR_ENROLLED") {
		t.Fatal("no enrollment evidence")
	}
	// Duplicate key, bad class and bad body are refused.
	if st, _ := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "again", "public_key": string(k.Public)}); st != http.StatusBadRequest {
		t.Fatalf("duplicate: %d", st)
	}
	if st, _ := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "x", "public_key": string(pkgtest.NewKey(t).Public), "classes": []string{"extreme"}}); st != http.StatusBadRequest {
		t.Fatalf("bad class: %d", st)
	}
	if st, _ := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"bogus": true}); st != http.StatusBadRequest {
		t.Fatalf("bad body: %d", st)
	}
	if st, _ := f.do("POST", "/api/v1/packages/trust", "", map[string]any{"name": "y"}); st != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", st)
	}
	if st, _ := f.do("DELETE", "/api/v1/packages/trust/team", f.token, nil); st != http.StatusOK {
		t.Fatalf("remove: %d", st)
	}
	if st, _ := f.do("DELETE", "/api/v1/packages/trust/team", f.token, nil); st != http.StatusNotFound {
		t.Fatalf("remove again: %d", st)
	}
	if !r.hasEvent("TRUST_ANCHOR_REMOVED") {
		t.Fatal("no removal evidence")
	}
}
