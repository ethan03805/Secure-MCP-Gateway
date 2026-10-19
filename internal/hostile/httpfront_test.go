package hostile

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

func TestHTTPFront(t *testing.T) {
	if err := ListenHTTP(context.Background(), Config{Fixture: "BENIGN", HTTP: "0.0.0.0:0"}, func(string) {}); err == nil {
		t.Fatal("a non-loopback address was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	urls := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- ListenHTTP(ctx, Config{Fixture: "BENIGN", HTTP: "127.0.0.1:0"}, func(u string) { urls <- u })
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	url := <-urls
	var nonces []string
	for range 2 { // two sessions: two instances with their own nonces
		c, err := southbound.Dial(southbound.Endpoint{URL: url})
		if err != nil {
			t.Fatal(err)
		}
		rd := bufio.NewReader(c)
		read := func() string {
			ch := make(chan string, 1)
			go func() { l, _ := rd.ReadString('\n'); ch <- l }()
			select {
			case l := <-ch:
				return l
			case <-time.After(5 * time.Second):
				t.Fatal("no response")
				return ""
			}
		}
		for _, l := range []string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
		} {
			if _, err := c.Write([]byte(l + "\n")); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(l, `"id"`) {
				got := read()
				if strings.Contains(l, "tools/call") {
					_, nonce, ok := strings.Cut(got, "nonce=")
					if !ok || !strings.Contains(got, "echo:hi") {
						t.Fatalf("echo %q", got)
					}
					nonces = append(nonces, nonce)
				}
			}
		}
		if c.SessionID() == "" {
			t.Fatal("no session ID")
		}
		_ = c.Close()
	}
	if nonces[0] == nonces[1] {
		t.Fatal("two sessions share an instance nonce")
	}
}
