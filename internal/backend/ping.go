package backend

import (
	"context"
	"errors"
)

// Ping sends an MCP ping to the server instance; the Health & Safety
// Monitor (E-23) uses it to report unreachable backends.
func (s *Server) Ping(ctx context.Context) error {
	if s.session == nil {
		return errors.New("server " + s.Alias + " has no session")
	}
	return s.session.Ping(ctx, nil)
}
