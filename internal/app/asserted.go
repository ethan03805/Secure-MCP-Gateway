package app

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
)

// recordAssertion records text a server instance asserted (stderr, a
// JSON-RPC error message, a notification) as a server_asserted event
// attributed to the instance (SR-6.18-1, backend.Assertion.Event).
func (a *App) recordAssertion(x backend.Assertion) {
	if a.Evidence == nil {
		return
	}
	if err := a.Evidence.Record(x.Event()); err != nil && a.log != nil {
		a.log.Warn("server-asserted evidence not recorded", "server", x.Server, "err", err)
	}
}
