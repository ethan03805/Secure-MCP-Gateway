//go:build !windows

package winpipe

import (
	"context"
	"net"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// Listener is the Windows named-pipe listener; off Windows Listen fails.
type Listener struct{ net.Listener }

// Listen returns ErrNotWindows.
func Listen(string, []winsec.Entry) (*Listener, error) { return nil, ErrNotWindows }

// Conn is a pipe connection (Windows only).
type Conn struct{ net.Conn }

// ClientSID returns ErrNotWindows.
func (*Conn) ClientSID() (string, error) { return "", ErrNotWindows }

// Dial returns ErrNotWindows.
func Dial(context.Context, string) (net.Conn, error) { return nil, ErrNotWindows }

// DACL returns ErrNotWindows.
func DACL(string) (protected, null bool, entries []winsec.Entry, err error) {
	return false, false, nil, ErrNotWindows
}
