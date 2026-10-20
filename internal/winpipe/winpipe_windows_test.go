//go:build windows

package winpipe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// TestWindowsPipeListenDialIdentify: a client reaches the listener, the
// server reads the client's user SID from its token (FR-21.9), lines go
// both ways, several clients connect in turn, and Close ends a blocked
// Accept. Partial: the Gateway's use of the pipe is internal/edge.
func TestWindowsPipeListenDialIdentify(t *testing.T) {
	reqtest.Partial(t, "FR-21.9")
	self, err := winsec.ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf(`\\.\pipe\smcp-winpipe-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	ln, err := Listen(name, Entries(self))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			c, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sid, err := c.(*Conn).ClientSID()
				if err != nil {
					return
				}
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				fmt.Fprintf(c, "%s %s", sid, line)
			}(c)
		}
		done <- nil
	}()
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := Dial(ctx, name)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "hello %d\n", i)
		got, err := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if err != nil || got != fmt.Sprintf("%s hello %d\n", self, i) {
			t.Fatalf("reply %q %v", got, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		accepted <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end a blocked Accept")
	}
}

// TestWindowsPipeListenerDACL: the listener reads the pipe's descriptor
// through a server instance (SR-2.8-6) before any Accept, while an Accept
// waits and between Accepts, and it matches what a client handle reads:
// protected, NETWORK and ANONYMOUS LOGON denied, this account allowed
// read and write, no other SID allowed.
func TestWindowsPipeListenerDACL(t *testing.T) {
	reqtest.Partial(t, "SR-2.8-6")
	self, err := winsec.ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf(`\\.\pipe\smcp-winpipe-dacl-%d-%d`, os.Getpid(), time.Now().UnixNano())
	ln, err := Listen(name, Entries(self))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	check := func(when string, protected, null bool, entries []winsec.Entry, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		if !protected || null {
			t.Fatalf("%s: protected=%v null=%v", when, protected, null)
		}
		denied := map[string]bool{}
		allowed := false
		for _, e := range entries {
			switch {
			case e.Deny:
				denied[e.SID] = true
			case e.SID != self:
				t.Errorf("%s: pipe grants %s", when, e)
			case e.Access&0x3 != 0x3:
				t.Errorf("%s: this account lacks read and write: %s", when, e)
			default:
				allowed = true
			}
		}
		if !allowed || !denied[winsec.SIDNetwork] || !denied[winsec.SIDAnonymous] {
			t.Fatalf("%s: entries %v", when, entries)
		}
	}
	p, n, e, err := ln.DACL()
	check("before Accept", p, n, e, err)

	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	time.Sleep(100 * time.Millisecond) // Accept waits on the first instance
	p, n, e, err = ln.DACL()
	check("during Accept", p, n, e, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case sc := <-accepted:
		sc.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not serve the client")
	}
	c.Close()

	// Between Accepts the instance the next Accept serves already exists
	// (SR-19). A client handle on it, with nobody accepting, reads the
	// same descriptor.
	p, n, e, err = ln.DACL()
	check("between Accepts", p, n, e, err)
	p, n, e, err = DACL(name)
	check("client handle", p, n, e, err)
}

// TestWindowsPipeNameHeldBetweenAccepts: security review v1.3, SR-19.
// After a connection is accepted and closed, and before the next Accept,
// the pipe name stays held by an instance of the listener, so another
// process cannot create it (FILE_FLAG_FIRST_PIPE_INSTANCE fails) and the
// listener's next instance cannot join a pipe someone else created.
func TestWindowsPipeNameHeldBetweenAccepts(t *testing.T) {
	reqtest.Partial(t, "SR-2.8-6")
	self, err := winsec.ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf(`\\.\pipe\smcp-winpipe-gap-%d-%d`, os.Getpid(), time.Now().UnixNano())
	ln, err := Listen(name, Entries(self))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case sc := <-accepted:
		sc.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not serve the client")
	}
	c.Close()
	// A squatter with the default security descriptor, as another account
	// would try it now that the served instance is closed.
	h, err := createInstance(name, nil, true)
	if err == nil {
		_ = windows.CloseHandle(h)
		t.Fatal("the pipe name was free between Accepts: another process could create it")
	}
	if !errors.Is(err, ErrSquatted) {
		t.Fatalf("squat attempt: %v", err)
	}
	// A client that opens the waiting instance and leaves before it is
	// accepted does not end the listener, and the next client is served.
	gone, err := Dial(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	gone.Close()
	errs := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		accepted <- c
	}()
	c2, err := Dial(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	select {
	case sc := <-accepted:
		sc.Close()
	case err := <-errs:
		t.Fatalf("Accept after a client left: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the next Accept did not serve the client")
	}
}
