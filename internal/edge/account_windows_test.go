//go:build windows

package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
	"github.com/ethan03805/secure-mcp-gateway/internal/winpipe"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
	"github.com/ethan03805/secure-mcp-gateway/internal/wintest"
)

// dialAs opens the pipe with u's token (the server sees u's user SID).
func dialAs(t *testing.T, u *wintest.User, path string) (net.Conn, error) {
	t.Helper()
	var c net.Conn
	var err error
	u.As(t, func() { c, err = dialHarness(path) })
	return c, err
}

// TestWindowsPipeAccounts runs the named-pipe harness listener with local
// accounts other than the Gateway's own, on a Windows runner (elevated, so
// the test can create them): a local harness group with two members, one
// registered as a peer and one not, and a third account outside the group.
//
// SR-2.8-6: the pipe's protected DACL grants read and write to the
// Gateway's account and the harness group only and denies NETWORK and
// ANONYMOUS LOGON; the account outside the group cannot open the pipe, a
// group member cannot open it through \\localhost\pipe\ (SMB), and a pipe
// name created before the Gateway is refused with pipe_squatted.
//
// FR-21.9: each client is identified by the user SID of its token: the
// registered account with its key gets one session, the registered
// account with a wrong key and the unregistered group member with the
// right key are refused, each refusal recorded with the client SID; the
// Gateway's own account (the per-user mode, where client and Gateway
// share the account) is identified and admitted the same way. Partial for
// FR-21.9: the Gateway here runs as the runner's administrator, not as
// NT SERVICE\smcpd of the machine mode.
func TestWindowsPipeAccounts(t *testing.T) {
	reqtest.Verifies(t, "SR-2.8-6")
	reqtest.Partial(t, "FR-21.9")
	group, groupSID := wintest.NewGroup(t)
	registered := wintest.NewUser(t, group)
	member := wintest.NewUser(t, group)
	outsider := wintest.NewUser(t)
	self := selfSID(t)

	path := fmt.Sprintf(`\\.\pipe\smcp-accounts-%d-%d`, os.Getpid(), testport.Free(t))
	h := newHarness(t, harnessOpts{toml: fmt.Sprintf(`[uds]
enabled = true
path = %q
group = %q
[[uds.peer]]
sid = %q
principal = "cc"
key_hash = %q
template = "ro"
[[uds.peer]]
sid = %q
principal = "self"
key_hash = %q
template = "ro"
`, path, group, registered.SID, udsKeyHash(t), self, udsKeyHash(t))})
	ln, err := h.gw.ListenUDS()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.gw.ServeUDS(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// The descriptor: protected, NETWORK and ANONYMOUS LOGON denied, read
	// and write for this account and the harness group, nothing else.
	protected, null, entries, err := ln.(*winpipe.Listener).DACL()
	if err != nil {
		t.Fatal(err)
	}
	if !protected || null {
		t.Fatalf("pipe DACL protected=%v null=%v", protected, null)
	}
	allowed, denied := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		switch {
		case e.Deny:
			denied[e.SID] = true
		case e.SID != self && e.SID != groupSID:
			t.Errorf("pipe grants %s", e)
		case e.Access&0x3 != 0x3:
			t.Errorf("%s lacks read and write: %s", e.SID, e)
		default:
			allowed[e.SID] = true
		}
	}
	if !allowed[self] || !allowed[groupSID] || !denied[winsec.SIDNetwork] || !denied[winsec.SIDAnonymous] {
		t.Fatalf("pipe DACL entries %v", entries)
	}

	// An account outside the group cannot open the pipe.
	if c, err := dialAs(t, outsider, path); err == nil {
		c.Close()
		t.Fatalf("%s (outside %s) opened the pipe", outsider.Name, group)
	} else if !errors.Is(err, os.ErrPermission) && !strings.Contains(err.Error(), "Access is denied") {
		t.Fatalf("%s: %v, want access denied", outsider.Name, err)
	}
	// A group member cannot reach it through the SMB path.
	remote := `\\localhost\pipe\` + path[len(`\\.\pipe\`):]
	if c, err := dialAs(t, registered, remote); err == nil {
		c.Close()
		t.Fatalf("%s opened %s", registered.Name, remote)
	}

	// The registered account with its key: one session for principal cc.
	c, err := dialAs(t, registered, path)
	if err != nil {
		t.Fatalf("%s: %v", registered.Name, err)
	}
	res := wrapUDS(t, c).authenticate(udsKey)
	r, _ := res["result"].(map[string]any)
	if r["sessionId"] == nil || r["principal"] != "cc" {
		t.Fatalf("registered account: %v", res)
	}

	refused := func(who *wintest.User, key, reason string) {
		t.Helper()
		c, err := dialAs(t, who, path)
		if err != nil {
			t.Fatalf("%s: %v", who.Name, err)
		}
		u := wrapUDS(t, c)
		if m := u.authenticate(key); errCode(m) != CodeSessionInvalid {
			t.Fatalf("%s: %v", who.Name, m)
		}
		if m := u.next(5 * time.Second); m != nil {
			t.Fatalf("%s: connection not closed: %v", who.Name, m)
		}
		e := h.rec.find(func(e audit.Event) bool {
			d, _ := e.Detail.(map[string]any)
			return e.Class == "auth_failure" && e.ReasonCode == reason && d["peer_sid"] == who.SID
		})
		if e == nil {
			t.Fatalf("no auth_failure %s recorded with client SID %s", reason, who.SID)
		}
	}
	refused(registered, "not the key", "UDS_KEY_INVALID")
	refused(member, udsKey, "UDS_PEER_UNREGISTERED")

	// The Gateway's own account, as in the per-user mode.
	own := dialUDS(t, path).authenticate(udsKey)
	if r, _ := own["result"].(map[string]any); r["principal"] != "self" {
		t.Fatalf("own account: %v", own)
	}
	sessions := 0
	for _, s := range h.store.List() {
		if s.Listener == "uds" {
			sessions++
		}
	}
	if sessions != 2 {
		t.Fatalf("%d pipe sessions, want 2 (the registered account and the Gateway's own)", sessions)
	}

	// Squatting: the Gateway refuses a pipe name that exists already.
	name := fmt.Sprintf(`\\.\pipe\smcp-squat-acct-%d-%d`, os.Getpid(), testport.Free(t))
	first, err := winpipe.Listen(name, winpipe.Entries(self))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	h2 := newHarness(t, harnessOpts{toml: fmt.Sprintf("[uds]\nenabled = true\npath = %q\ngroup = %q\n[[uds.peer]]\nsid = %q\nprincipal = \"cc\"\nkey_hash = %q\ntemplate = \"ro\"\n",
		name, group, registered.SID, udsKeyHash(t))})
	if _, err := h2.gw.ListenUDS(); !errors.Is(err, winpipe.ErrSquatted) || !strings.Contains(err.Error(), "pipe_squatted") {
		t.Fatalf("ListenUDS on a squatted name: %v, want pipe_squatted", err)
	}
}
