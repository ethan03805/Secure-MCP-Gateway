//go:build !windows

package edge

import (
	"net"
	"testing"
)

// dialHarness connects to the harness socket.
func dialHarness(path string) (net.Conn, error) { return net.Dial("unix", path) }

// selfSID is not used off Windows.
func selfSID(t *testing.T) string { t.Helper(); return "" }
