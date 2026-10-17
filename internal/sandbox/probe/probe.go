// Package probe is a hostile-fixture MCP server for sandbox tests. Each
// tool attempts something the Execution Sandbox (E-16) must prevent or the
// Runtime Monitor (E-17) must notice, and reports what happened as text.
// It never returns a tool error, so callers can match the outcome.
//
// Tools:
//
//	echo         returns text
//	net_connect  dials a TCP address ("blocked: ..." or "connected")
//	write_file   creates a file ("blocked: ..." or "wrote")
//	read_file    reads a file ("blocked: ..." or the content)
//	spawn        starts a copy of itself that sleeps (process creation)
//	alloc        allocates and touches the given number of MiB
//	identity     reports uid, gid and the uid_map of the process
//	http_get     fetches a URL through the proxy in HTTP_PROXY, if any
//	             ("blocked: ..." or "status <code>: <body>")
package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SleepArg makes the binary sleep instead of serving (used by spawn).
const SleepArg = "--probe-sleep"

type textArgs struct {
	Text string `json:"text" jsonschema:"text to return"`
}

type addrArgs struct {
	Address string `json:"address" jsonschema:"host:port to dial"`
}

type writeArgs struct {
	Path string `json:"path" jsonschema:"absolute path"`
	Text string `json:"text,omitempty" jsonschema:"content"`
}

type pathArgs struct {
	Path string `json:"path" jsonschema:"absolute path"`
}

type allocArgs struct {
	MiB int `json:"mib" jsonschema:"MiB to allocate"`
}

type urlArgs struct {
	URL string `json:"url" jsonschema:"http URL to fetch"`
}

type noArgs struct{}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// blocked reports a refused attempt as the tool's result: for the probe a
// failure is the expected outcome, not an error.
func blocked(err error) (*mcp.CallToolResult, any, error) {
	return text("blocked: " + err.Error()), nil, nil
}

// Server returns the probe MCP server.
func Server() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "smcp-sandbox-probe", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Return the text."},
		func(_ context.Context, _ *mcp.CallToolRequest, a textArgs) (*mcp.CallToolResult, any, error) {
			return text(a.Text), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "net_connect", Description: "Dial a TCP address."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a addrArgs) (*mcp.CallToolResult, any, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			c, err := d.DialContext(ctx, "tcp", a.Address)
			if err != nil {
				return blocked(err)
			}
			c.Close()
			return text("connected"), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "write_file", Description: "Create a file."},
		func(_ context.Context, _ *mcp.CallToolRequest, a writeArgs) (*mcp.CallToolResult, any, error) {
			if err := os.WriteFile(a.Path, []byte(a.Text), 0o600); err != nil {
				return blocked(err)
			}
			return text("wrote " + a.Path), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "read_file", Description: "Read a file."},
		func(_ context.Context, _ *mcp.CallToolRequest, a pathArgs) (*mcp.CallToolResult, any, error) {
			b, err := os.ReadFile(a.Path)
			if err != nil {
				return blocked(err)
			}
			return text(string(b)), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "spawn", Description: "Start a child process that sleeps for 30 seconds."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			exe, err := os.Executable()
			if err != nil {
				return blocked(err)
			}
			cmd := exec.Command(exe, SleepArg) // #nosec G204 -- the probe's own binary
			if err := cmd.Start(); err != nil {
				return blocked(err)
			}
			go func() { _ = cmd.Wait() }()
			return text(fmt.Sprintf("spawned %d", cmd.Process.Pid)), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "alloc", Description: "Allocate and touch memory."},
		func(_ context.Context, _ *mcp.CallToolRequest, a allocArgs) (*mcp.CallToolResult, any, error) {
			b := make([]byte, a.MiB<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			return text(fmt.Sprintf("allocated %d MiB", len(b)>>20)), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "http_get", Description: "Fetch a URL through the Egress Broker proxy (HTTP_PROXY)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a urlArgs) (*mcp.CallToolResult, any, error) {
			// The proxy is used for every destination, loopback included
			// (http.ProxyFromEnvironment would bypass it for 127.0.0.1).
			tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
			if p := os.Getenv("HTTP_PROXY"); p != "" {
				pu, err := url.Parse(p)
				if err != nil {
					return blocked(err)
				}
				tr.Proxy = http.ProxyURL(pu)
			}
			c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
			if err != nil {
				return blocked(err)
			}
			resp, err := c.Do(req) // #nosec G704 -- the probe's purpose is to attempt egress
			if err != nil {
				return blocked(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return text(fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "identity", Description: "Report process identity and user namespace mapping."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			m, _ := os.ReadFile("/proc/self/uid_map")
			st, _ := os.ReadFile("/proc/self/status")
			var keep []string
			for _, l := range strings.Split(string(st), "\n") {
				if strings.HasPrefix(l, "Cap") || strings.HasPrefix(l, "NoNewPrivs") || strings.HasPrefix(l, "Seccomp") {
					keep = append(keep, l)
				}
			}
			return text(fmt.Sprintf("uid=%d gid=%d\nuid_map=%s\n%s", os.Getuid(), os.Getgid(), strings.TrimSpace(string(m)), strings.Join(keep, "\n"))), nil, nil
		})
	return s
}

// Main runs the probe: it sleeps when given SleepArg, else serves MCP on
// stdio until stdin closes.
func Main(args []string) int {
	if len(args) > 0 && args[0] == SleepArg {
		time.Sleep(30 * time.Second)
		return 0
	}
	if err := Server().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		return 1
	}
	return 0
}
