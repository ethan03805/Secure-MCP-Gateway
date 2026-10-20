package library

import (
	"errors"
	"slices"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// fakeContainment records the placement calls.
type fakeContainment struct {
	fail    error
	ensured []winsandbox.PlacementRequest
	removed []string
	have    map[string]winsandbox.Placement
}

func (f *fakeContainment) Ensure(r winsandbox.PlacementRequest) (winsandbox.Placement, error) {
	if f.fail != nil {
		return winsandbox.Placement{}, f.fail
	}
	f.ensured = append(f.ensured, r)
	pl := winsandbox.Placement{ServerID: r.ServerID, Revision: r.Revision, Profile: winsandbox.ProfileName(r.ServerID, r.Revision),
		Tree: r.Tree, Scratch: r.Scratch, Roots: r.Roots, BrokerPort: 4242}
	f.have[r.ServerID+"@"+r.Revision] = pl
	return pl, nil
}

func (f *fakeContainment) Remove(id, rev string) error {
	f.removed = append(f.removed, id+"@"+rev)
	delete(f.have, id+"@"+rev)
	return nil
}

func (f *fakeContainment) Lookup(id, rev string) (winsandbox.Placement, bool) {
	pl, ok := f.have[id+"@"+rev]
	return pl, ok
}

// TestContainmentFollowsRegistryStates: with a containment (the Windows
// machine mode), enabling a revision sets up its placement with the
// unpacked tree, the configured alias's scratch directory and the
// manifest's slots that the configuration binds (SR-4.6-2); a failure
// refuses the enable with CONTAINMENT_FAILED; a superseded, disabled or
// retired revision's placement is removed, a suspended one's kept; a start
// carries the profile and the broker port, and refuses a revision without
// a placement. Partial for FR-21.13, SR-4.6-2 and FR-21.14: the Windows
// placement itself is tested on Windows.
func TestContainmentFollowsRegistryStates(t *testing.T) {
	reqtest.Partial(t, "FR-21.13", "SR-4.6-2", "FR-21.14")
	e := newEnv(t)
	fc := &fakeContainment{have: map[string]winsandbox.Placement{}}
	docs, out := t.TempDir(), t.TempDir()
	e.lib.containment = fc
	e.lib.bindings = func(id string) (SlotBinding, bool) {
		return SlotBinding{Alias: "files", Slots: map[string]string{"docs": docs, "out": out, "undeclared": "/x"}}, id == "srv"
	}
	slots := func(m *packaging.Manifest, _ *packaging.Provenance) {
		m.Capabilities.Filesystem = []packaging.FilesystemSlot{{Slot: "docs", Mode: "ro"}, {Slot: "out", Mode: "rw"}, {Slot: "unbound", Mode: "rw"}}
	}
	for _, rev := range []string{"1", "2"} {
		if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "srv", Revision: rev, Alias: "files", Edit: slots}), ImportOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	fc.fail = errors.New("no administrator")
	if _, err := e.lib.Enable("srv", "1", EnableOptions{}); reason(err) != ReasonContainment {
		t.Fatalf("enable with a failing containment: %v", err)
	}
	if _, ok := e.lib.enabledRevision("srv"); ok {
		t.Fatal("revision enabled without containment")
	}
	fc.fail = nil
	r1, err := e.lib.Enable("srv", "1", EnableOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fc.ensured) != 1 {
		t.Fatalf("ensure calls %+v", fc.ensured)
	}
	req := fc.ensured[0]
	wantRoots := []winsandbox.PathGrant{{Path: docs}, {Path: out, Write: true}}
	if req.Tree != e.lib.TreePath(r1.ArtifactSHA256) || req.Scratch != e.lib.path("work", "files") || !slices.Equal(req.Roots, wantRoots) {
		t.Fatalf("placement request %+v", req)
	}

	rt := NewRuntime(e.lib, RuntimeOptions{})
	sc, err := rt.Resolve(config.Server{Alias: "files", Package: "srv", Slots: map[string]string{"docs": docs, "out": out}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Container != winsandbox.ProfileName("srv", "1") || sc.EgressProxyPort != 4242 {
		t.Fatalf("resolved %q port %d", sc.Container, sc.EgressProxyPort)
	}
	if _, err := rt.Resolve(config.Server{Alias: "other", Package: "srv"}, false); reason(err) != ReasonContainment {
		t.Fatalf("start under another alias than the placement's scratch: %v", err)
	}

	if _, err := e.lib.Enable("srv", "2", EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fc.removed, []string{"srv@1"}) {
		t.Fatalf("superseded revision not released: %v", fc.removed)
	}
	if _, _, err := e.lib.SetState("srv", "2", StateSuspended, "test", "op"); err != nil {
		t.Fatal(err)
	}
	if len(fc.removed) != 1 {
		t.Fatalf("suspension released the placement: %v", fc.removed)
	}
	if _, _, err := e.lib.SetState("srv", "2", StateVerifiedDisabled, "test", "op"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fc.removed, []string{"srv@1", "srv@2"}) {
		t.Fatalf("disabled revision not released: %v", fc.removed)
	}
	delete(fc.have, "srv@2")
	if _, err := e.lib.Enable("srv", "2", EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	delete(fc.have, "srv@2") // the placement vanished
	if _, err := rt.Resolve(config.Server{Alias: "files", Package: "srv"}, false); reason(err) != ReasonContainment {
		t.Fatalf("start without a placement: %v", err)
	}
}
