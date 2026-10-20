package winsandbox

import (
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/health"
)

// ContextForgeUnconfinedCheck is the health check of FR-22.25 for the
// bundled ContextForge instance on Windows: while running reports true, the
// Gateway is degraded with the non-critical cause contextforge_unconfined,
// because the instance runs in a Job Object with the CP-24 limits but not
// in an AppContainer, in every installation mode.
func ContextForgeUnconfinedCheck(running func() bool) health.Check {
	return func(time.Time) []health.Cause {
		if running == nil || !running() {
			return nil
		}
		return []health.Cause{{Name: CauseContextForgeUnconfined,
			Detail: "the bundled ContextForge instance runs in a Job Object with resource limits, not in an AppContainer"}}
	}
}
