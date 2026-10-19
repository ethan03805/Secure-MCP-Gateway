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
