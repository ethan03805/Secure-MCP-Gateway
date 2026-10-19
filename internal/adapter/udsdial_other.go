//go:build !windows

package adapter

import (
	"context"
	"net"
)

// dialHarness connects to the Gateway's Unix-domain harness socket.
func dialHarness(ctx context.Context, socket string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socket)
}
