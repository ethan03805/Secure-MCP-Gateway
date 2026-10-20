package southbound

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound/sbtest"
)

// TestMcpNameEncoding: Mcp-Name carries a tool, prompt or resource name
// as plain text when it can, and in the Base64 sentinel form otherwise
// (FR-5.29); the line the Conn returns is the server's response.
func TestMcpNameEncoding(t *testing.T) {
	s := sbtest.New()
	t.Cleanup(s.Close)
	c, err := Dial(Endpoint{URL: s.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	rd := bufio.NewReader(c)
	cases := []struct{ line, want string }{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{}}}`, "get_weather"},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wetter-für-köln","arguments":{}}}`, "=?base64?d2V0dGVyLWbDvHIta8O2bG4=?="},
		{`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":" padded"}}`, "=?base64?IHBhZGRlZA==?="},
		{`{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///projects/app/config.json"}}`, "file:///projects/app/config.json"},
		{`{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"=?base64?x?="}}`, "=?base64?PT9iYXNlNjQ/eD89?="},
	}
	for i, tc := range cases {
		if _, err := c.Write([]byte(tc.line + "\n")); err != nil {
			t.Fatal(err)
		}
		done := make(chan string, 1)
		go func() {
			l, _ := rd.ReadString('\n')
			done <- l
		}()
		select {
		case l := <-done:
			if !strings.Contains(l, `"id":`) {
				t.Fatalf("case %d: got %q", i, l)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("case %d: no response", i)
		}
		posts := s.Posts("")
		h := posts[len(posts)-1].Header
		if h.Get("Mcp-Name") != tc.want {
			t.Errorf("case %d: Mcp-Name %q, want %q", i, h.Get("Mcp-Name"), tc.want)
		}
		if dec, _ := DecodeValue(h.Get("Mcp-Name")); i == 1 && dec != "wetter-für-köln" {
			t.Errorf("decoded %q", dec)
		}
	}
}

// TestTokenSource: a TokenSource is asked for each request, so a token
// renewed while the connection is open is sent with the next request; a
// Launcher passes the spec's TokenSource and ignores the token variables
// (SRS FR-22.36, FR-22.29).
func TestTokenSource(t *testing.T) {
	reqtest.Partial(t, "FR-22.36", "FR-22.29")
	s := sbtest.New()
	t.Cleanup(s.Close)
	var mu sync.Mutex
	tok := "first-token"
	l := &Launcher{Inner: pipeline.SubprocessLauncher{}}
	p, err := l.Launch(context.Background(), pipeline.ServerSpec{URL: s.URL, Env: map[string]string{TokenEnv: "env-token"},
		TokenSource: func() string { mu.Lock(); defer mu.Unlock(); return tok }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	rd := bufio.NewReader(p)
	send := func(id int) {
		t.Helper()
		if _, err := fmt.Fprintf(p, `{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{}}`+"\n", id); err != nil {
			t.Fatal(err)
		}
		if l, err := rd.ReadString('\n'); err != nil || !strings.Contains(l, `"id":`) {
			t.Fatalf("response %q %v", l, err)
		}
	}
	send(1)
	mu.Lock()
	tok = "renewed-token"
	mu.Unlock()
	send(2)
	posts := s.Posts("")
	if len(posts) < 2 {
		t.Fatalf("%d posts", len(posts))
	}
	if a, b := posts[len(posts)-2].Header.Get("Authorization"), posts[len(posts)-1].Header.Get("Authorization"); a != "Bearer first-token" || b != "Bearer renewed-token" {
		t.Fatalf("authorization %q then %q", a, b)
	}
}
