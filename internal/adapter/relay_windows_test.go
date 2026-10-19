//go:build windows

package adapter_test

import "testing"

// TestWindowsPipeRelay runs TestRelayUnixSocket, which on Windows relays
// smcp-stdio over the CP-02 named pipe (FR-21.16), under a name the
// windows CI job collects for the requirement report.
func TestWindowsPipeRelay(t *testing.T) { TestRelayUnixSocket(t) }
