//go:build windows

package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
	"github.com/ethan03805/secure-mcp-gateway/internal/winpipe"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// dialHarness connects to the harness named pipe.
func dialHarness(path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return winpipe.Dial(ctx, path)
}

func selfSID(t *testing.T) string {
	t.Helper()
	s, err := winsec.ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestWindowsUDSRefused: the Unix-domain socket listener is never used on
// Windows; the profile is served over the named pipe (FR-21.8).
func TestWindowsUDSRefused(t *testing.T) {
	if err := udsSupported(); err == nil {
		t.Fatal("udsSupported() = nil on Windows")
	}
}

// TestWindowsPipePeerAndKey runs the FR-2.15 peer and key checks over the
// named pipe: a session only for the registered user SID with its key;
// the wrong key and an unregistered SID refused and recorded (FR-21.9).
// Partial: the machine mode and a second Windows account are not run here.
func TestWindowsPipePeerAndKey(t *testing.T) {
	reqtest.Partial(t, "FR-21.8", "FR-21.9")
	TestUDSPeerAndKey(t)
}

// TestWindowsPipeTransport runs the FR-1.47 transport fixtures over the
// named pipe (FR-21.8): framing, pipelining, listen streams, cancellation
// and the session ending with the connection.
func TestWindowsPipeTransport(t *testing.T) {
	reqtest.Partial(t, "FR-21.8")
	TestUDSHarnessTransport(t)
}

// TestWindowsPipeSecurityDescriptor reads the pipe's DACL (SR-2.8-6):
// protected, deny NETWORK and ANONYMOUS LOGON, read and write for this
// account and no other SID; and a pipe name that exists before the
// Gateway creates it is refused with pipe_squatted. Partial: the
// connection over SMB (\\localhost\pipe\) and from a user outside the
// group need a second account.
func TestWindowsPipeSecurityDescriptor(t *testing.T) {
	reqtest.Partial(t, "SR-2.8-6")
	h, path := udsHarness(t, harnessOpts{}, os.Getuid(), "ro")
	_ = h
	protected, null, entries, err := winpipe.DACL(path)
	if err != nil {
		t.Fatal(err)
	}
	self := selfSID(t)
	if !protected || null {
		t.Fatalf("pipe DACL protected=%v null=%v", protected, null)
	}
	denied := map[string]bool{}
	for _, e := range entries {
		switch {
		case e.Deny:
			denied[e.SID] = true
		case e.SID != self:
			t.Errorf("pipe grants %s", e)
		case e.Access&0x3 != 0x3:
			t.Errorf("this account lacks read and write: %s", e)
		}
	}
	if !denied[winsec.SIDNetwork] || !denied[winsec.SIDAnonymous] {
		t.Fatalf("NETWORK and ANONYMOUS LOGON not denied: %v", entries)
	}
	// Remote clients are rejected (PIPE_REJECT_REMOTE_CLIENTS): the pipe
	// opened through the SMB loopback path fails.
	remote := `\\localhost\pipe\` + path[len(`\\.\pipe\`):]
	if c, err := dialHarness(remote); err == nil {
		c.Close()
		t.Fatalf("%s accepted a remote-path client", remote)
	}

	// Squatting: the name exists before the listener.
	name := fmt.Sprintf(`\\.\pipe\smcp-squat-%d-%d`, os.Getpid(), testport.Free(t))
	first, err := winpipe.Listen(name, winpipe.Entries(self))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := winpipe.Listen(name, winpipe.Entries(self)); !errors.Is(err, winpipe.ErrSquatted) {
		t.Fatalf("second listener on an existing name: %v, want ErrSquatted", err)
	}
}
