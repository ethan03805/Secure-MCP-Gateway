package bundle

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ManagedPlatform is the platform name of the managed-process form in
// verification records and evidence.
const ManagedPlatform = "managed-process"

// ReasonVersionMismatch: the managed process's environment holds another
// ContextForge release than the release lock pins.
const ReasonVersionMismatch = "CONTEXTFORGE_VERSION_MISMATCH"

// ProcessVerifier checks the managed-process form before a start: the
// operator's environment must hold the ContextForge release the release
// lock pins. It is a version check of an operator-supplied environment,
// not the per-wheel SHA-256 verification of FR-22.20, which needs the
// wheel set in the release lock.
type ProcessVerifier struct {
	Python string
	// Run runs the interpreter (tests replace it).
	Run func(ctx context.Context, python string, args ...string) (string, error)
}

func (v ProcessVerifier) run(ctx context.Context, args ...string) (string, error) {
	if v.Run != nil {
		return v.Run(ctx, v.Python, args...)
	}
	out, err := exec.CommandContext(ctx, v.Python, args...).CombinedOutput() //nolint:gosec // G204: the configured interpreter
	return strings.TrimSpace(string(out)), err
}

// Verify implements the Connector's ImageVerifier.
func (v ProcessVerifier) Verify(ctx context.Context, r *contextforge.LockedRelease, _ string, now time.Time) (*Verification, error) {
	out, err := v.run(ctx, "-c", "import importlib.metadata as m; print(m.version('mcp-contextforge-gateway'))")
	if err != nil {
		return nil, packaging.Wrap(ReasonVersionMismatch, "reading the ContextForge version of "+v.Python, fmt.Errorf("%w: %s", err, out))
	}
	lines := strings.Fields(out)
	got := ""
	if len(lines) > 0 {
		got = lines[len(lines)-1]
	}
	if want := strings.TrimPrefix(r.Version, "v"); got != want {
		return nil, packaging.Errf(ReasonVersionMismatch, "%s holds ContextForge %q; the release lock pins %s", v.Python, got, want)
	}
	return &Verification{Version: r.Version, SourceTag: "operator environment " + v.Python, Platform: ManagedPlatform, VerifiedAt: now}, nil
}

// LocalDigestOK implements the Connector's ImageVerifier; the managed
// process has no image.
func (ProcessVerifier) LocalDigestOK(context.Context, *Verification, string) error { return nil }
