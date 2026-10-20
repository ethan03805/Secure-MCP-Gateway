package connector

import (
	"context"
	"net/netip"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
)

// Runner is the bundled instance as the Connector drives it: the
// container of the pinned image (bundle.Instance), the managed process on
// Windows (FR-22.25), or a stand-in in tests.
type Runner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Status() bundle.Status
	BaseURL() string
	Healthy() bool
	// AdminToken mints a short-lived administrator token (I-43).
	AdminToken(ttl time.Duration) (string, error)
	RemoveVolume(ctx context.Context) error
	RemoveImage(ctx context.Context) error
	// HostAccess says where the hosted egress listener binds and how the
	// instance reaches it (FR-22.40).
	HostAccess(ctx context.Context) (bundle.HostAccess, error)
	// SetSSRFAllowed and SetEgressAllow apply to the next start: the
	// SSRF allowlist (FR-22.27) and the one destination the Enforced
	// containment admits (FR-22.24).
	SetSSRFAllowed(nets []string)
	SetEgressAllow(ap netip.AddrPort)
}

// ImageVerifier verifies the pinned release's artifacts before a start
// (FR-22.19).
type ImageVerifier interface {
	Verify(ctx context.Context, r *contextforge.LockedRelease, platform string, now time.Time) (*bundle.Verification, error)
	LocalDigestOK(ctx context.Context, ver *bundle.Verification, reference string) error
}

var (
	_ Runner        = (*bundle.Instance)(nil)
	_ ImageVerifier = (*bundle.Verifier)(nil)
)
