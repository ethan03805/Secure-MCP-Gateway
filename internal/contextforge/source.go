package contextforge

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// PinnedCatalog returns the catalog of the ContextForge release pinned in
// the Gateway's release lock. The file is compiled into the Gateway and its
// SHA-256 is checked against the lock before it is parsed (FR-22.1).
func PinnedCatalog() (*Catalog, error) {
	return LoadPinned(pinnedCatalogYAML, ReleaseLock())
}

// LoadPinned parses raw as the catalog of the release pinned by l. It
// refuses raw with CATALOG_DIGEST_MISMATCH when its SHA-256 differs from
// the lock, before parsing it.
func LoadPinned(raw []byte, l *Lock) (*Catalog, error) {
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if got != l.ContextForge.Catalog.SHA256 {
		return nil, packaging.Errf(ReasonCatalogDigestMismatch,
			"catalog SHA-256 %s differs from the release lock (%s for ContextForge %s)", got, l.ContextForge.Catalog.SHA256, l.ContextForge.Version)
	}
	c, err := ParseCatalog(raw)
	if err != nil {
		return nil, err
	}
	c.Origin, c.Release = OriginPinned, l.ContextForge.Version
	return c, nil
}

// LoadConfirmed parses raw as an operator-supplied catalog whose SHA-256
// the operator confirmed. It refuses raw with CATALOG_DIGEST_MISMATCH when
// no digest is confirmed or the digest differs, before parsing it
// (FR-22.1).
func LoadConfirmed(raw []byte, confirmed string) (*Catalog, error) {
	confirmed = strings.ToLower(strings.TrimSpace(confirmed))
	if confirmed == "" {
		return nil, packaging.Errf(ReasonCatalogDigestMismatch,
			"an operator-supplied catalog needs the SHA-256 the operator confirms")
	}
	if !hex64.MatchString(confirmed) {
		return nil, packaging.Errf(ReasonCatalogDigestMismatch, "the confirmed SHA-256 %q is not 64 hexadecimal digits", confirmed)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != confirmed {
		return nil, packaging.Errf(ReasonCatalogDigestMismatch, "catalog SHA-256 %s differs from the confirmed %s", got, confirmed)
	}
	c, err := ParseCatalog(raw)
	if err != nil {
		return nil, err
	}
	c.Origin = OriginOperator
	return c, nil
}
