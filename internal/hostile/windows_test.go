//go:build windows

package hostile

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The resource rows of Appendix L (HF-20, HF-21) against the Windows
// launcher: the fixture runs as a backend started by the Server Runtime
// Manager's Windows path, in its own Job Object with the configured
// limits (FR-21.12), and an MCP client drives it over the instance's pipes.
// The full suite (TestHostileFixtures) needs a running smcpd, which starts on
// Windows once the FR-21.5 and FR-21.10 key protection lands.

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func launchWindowsFixture(t *testing.T, lim pipeline.ResourceLimits, args ...string) (pipeline.Process, *mcp.ClientSession) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l := pipeline.SubprocessLauncher{TerminateAfter: time.Second, Limits: func(pipeline.ServerSpec) pipeline.ResourceLimits { return lim }}
	p, err := l.Launch(context.Background(), pipeline.ServerSpec{Alias: "h", Command: exe, Args: append([]string{SelfFlag}, args...),
		Env: map[string]string{"SYSTEMROOT": os.Getenv("SYSTEMROOT")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(),
		&mcp.IOTransport{Reader: io.NopCloser(p), Writer: nopWriteCloser{p}}, nil)
	if err != nil {
		t.Fatalf("connect: %v; stderr %q", err, p.Stderr())
	}
	t.Cleanup(func() { cs.Close() })
	return p, cs
}

func waitStderr(t *testing.T, p pipeline.Process, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(p.Stderr(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("stderr has no %q: %q", want, p.Stderr())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestWindowsJobForkBomb (HF-20): growth stops at the Job Object's active
// process limit and the instance is ended.
func TestWindowsJobForkBomb(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	p, cs := launchWindowsFixture(t, pipeline.ResourceLimits{Processes: 8}, "-fixture", "HF-20", "-children", "64")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "spawn", Arguments: map[string]any{}})
	if err == nil {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok && strings.HasPrefix(tc.Text, "spawned 64") {
				t.Fatalf("fork bomb not limited: %s", tc.Text)
			}
		}
	}
	waitStderr(t, p, "broke its processes limit")
}

// TestWindowsJobMemoryBlowUp (HF-21): allocation stops at the Job Object's
// memory limit and the instance is ended.
func TestWindowsJobMemoryBlowUp(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	p, cs := launchWindowsFixture(t, pipeline.ResourceLimits{MemoryBytes: 96 << 20}, "-fixture", "HF-21", "-alloc-mib", "256")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "alloc", Arguments: map[string]any{}})
	if err == nil {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok && strings.HasPrefix(tc.Text, "allocated 256") {
				t.Fatalf("memory not limited: %s", tc.Text)
			}
		}
	}
	waitStderr(t, p, "broke its memory limit")
}
