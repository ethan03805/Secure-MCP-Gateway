//go:build windows

package adapter

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/winpipe"
)

// dialHarness connects to the Gateway's harness named pipe (FR-21.16);
// Windows has no Unix-domain harness socket.
func dialHarness(ctx context.Context, socket string) (net.Conn, error) {
	if !strings.HasPrefix(strings.ToLower(socket), `\\.\pipe\`) {
		return nil, fmt.Errorf(`[gateway] socket must name the Gateway's named pipe (\\.\pipe\...) on Windows, not %q`, socket)
	}
	return winpipe.Dial(ctx, socket)
}
