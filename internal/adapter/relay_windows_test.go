//go:build windows

package adapter_test

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsPipeRelay runs TestRelayUnixSocket, which on Windows relays
// smcp-stdio over the CP-02 named pipe (FR-21.16), under a name the
// windows CI job collects for the requirement report.
func TestWindowsPipeRelay(t *testing.T) { TestRelayUnixSocket(t) }

// TestWindowsCredentialPath: the CP-43 credential file on Windows is
// %APPDATA%\smcp\credentials.toml (FR-21.16).
func TestWindowsCredentialPath(t *testing.T) {
	reqtest.Partial(t, "FR-21.16")
	t.Setenv("SMCP_CREDENTIALS", "")
	t.Setenv("APPDATA", `C:\Users\u\AppData\Roaming`)
	if got := adapter.DefaultPath(); got != `C:\Users\u\AppData\Roaming\smcp\credentials.toml` {
		t.Fatalf("DefaultPath = %s", got)
	}
}
