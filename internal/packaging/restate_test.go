package packaging_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
)

func TestRestateKeepsPackageConsistent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pkg")
	pkgtest.Build(t, dir, pkgtest.Spec{ID: "fx-restate", Revision: "1.0.0"})
	td := &packaging.TrustDecision{Actor: "op", Time: "2026-10-19T00:00:00Z", PresentedSHA256: packaging.SHA256Hex([]byte("text")), Text: "text"}
	err := packaging.Restate(dir, func(p *packaging.Provenance) error {
		p.ContextForge = &packaging.ContextForgeOrigin{CatalogSHA256: "c", EntryID: "e", EntrySHA256: "d", Class: "local"}
		p.TrustDecision = td
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	k := pkgtest.NewKey(t)
	if err := packaging.Sign(dir, k.Private, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, err := packaging.ParsePublicKey(k.Public)
	if err != nil {
		t.Fatal(err)
	}
	p, err := packaging.Verify(dir, packaging.VerifyOptions{Keys: packaging.PublicKeyResolver(pub)})
	if err != nil {
		t.Fatalf("restated package does not verify: %v", err)
	}
	if p.Provenance.TrustDecision == nil || *p.Provenance.TrustDecision != *td || p.Provenance.ContextForge.EntryID != "e" {
		t.Fatalf("provenance %+v", p.Provenance)
	}
	// A signed package is not restated.
	if err := packaging.Restate(dir, func(*packaging.Provenance) error { return nil }); err == nil {
		t.Fatal("signed package restated")
	}
}
