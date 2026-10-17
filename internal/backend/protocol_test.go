package backend

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/hostile"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// hostileLauncher runs an Appendix L fixture (internal/hostile) in process
// over pipes. Command names the fixture: /fixture/HF-xx.
type hostileLauncher struct {
	launches atomic.Int32
	mu       sync.Mutex
	procs    []*pipeProc
}

func (*hostileLauncher) Name() string   { return "hostile" }
func (*hostileLauncher) Confined() bool { return false }

type pipeProc struct {
	io.Reader
	io.Writer
	closers []io.Closer
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
}

func (p *pipeProc) Close() error {
	p.once.Do(func() {
		p.cancel()
		for _, c := range p.closers {
			c.Close()
		}
		<-p.done
	})
	return nil
}
func (p *pipeProc) Stderr() string { return "" }

func (l *hostileLauncher) Launch(_ context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	l.launches.Add(1)
	fixture := strings.TrimPrefix(spec.Command, "/fixture/")
	toSrvR, toSrvW := io.Pipe()
	fromSrvR, fromSrvW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	p := &pipeProc{Reader: fromSrvR, Writer: toSrvW, closers: []io.Closer{toSrvW, toSrvR, fromSrvR, fromSrvW}, cancel: cancel, done: make(chan struct{})}
	l.mu.Lock()
	l.procs = append(l.procs, p)
	l.mu.Unlock()
	go func() {
		defer close(p.done)
		_ = hostile.Serve(ctx, hostile.Config{Fixture: fixture, DripEvery: time.Second}, toSrvR, fromSrvW)
		fromSrvW.Close()
	}()
	return p, nil
}

func startFixture(t *testing.T, timeout time.Duration, fixtures ...string) (*Registry, *pipeline.Capabilities, *hostileLauncher) {
	t.Helper()
	caps := pipeline.NewCapabilities(time.Minute)
	l := &hostileLauncher{}
	var servers []config.Server
	for i, f := range fixtures {
		servers = append(servers, config.Server{Alias: string(rune('a' + i)), Command: "/fixture/" + f})
	}
	r, err := Start(context.Background(), servers, Options{Limits: Limits{PerPrincipal: 4, Total: 4, Queue: 4, UpstreamTimeout: timeout, ResultBytes: 1 << 20},
		Launcher: l, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r, caps, l
}

// TestServerInitiatedRequestsRefused: roots/list and sampling/createMessage
// from a backend are answered with -32601 by the Gateway (FR-5.20); the SDK
// client never answers them, and the Gateway declares no client
// capabilities southbound (SR-5.6-2; see TestNoSouthboundCapabilities).
func TestServerInitiatedRequestsRefused(t *testing.T) {
	reqtest.Partial(t, "FR-5.20")
	r, caps, _ := startFixture(t, 10*time.Second, "HF-26")
	res, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_legacy"), "c1", `{}`))
	if err != nil {
		t.Fatal(err)
	}
	got := res.Content[0].(*mcp.TextContent).Text
	if got != "roots/list=error(-32601) sampling/createMessage=error(-32601)" {
		t.Fatalf("fixture saw %q", got)
	}
	if n := r.Servers()["a"].RefusedRequests(); n != 2 {
		t.Fatalf("refused %d", n)
	}
	// ping is still answered (FR-5.20).
	f := newFrameFilter(strings.NewReader(`{"jsonrpc":"2.0","id":"p","method":"ping"}`+"\n"+`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`+"\n"), 1<<10)
	out, _ := io.ReadAll(f)
	if strings.Count(string(out), "\n") != 2 || f.refusedN.Load() != 0 {
		t.Fatalf("ping or notification screened: %q", out)
	}
}

// TestNoSouthboundCapabilities inspects the initialize request the Gateway
// sends to a backend (SR-5.6-2).
func TestNoSouthboundCapabilities(t *testing.T) {
	reqtest.Verifies(t, "SR-5.6-2")
	var got *mcp.InitializeParams
	var mu sync.Mutex
	build := func() *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{Name: "caps", Version: "1"}, nil)
		mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			mu.Lock()
			got = req.Session.InitializeParams()
			mu.Unlock()
			return &mcp.CallToolResult{}, nil, nil
		})
		return s
	}
	caps := pipeline.NewCapabilities(time.Minute)
	r, err := Start(context.Background(), []config.Server{{Alias: "m", Command: "/fake/mem"}},
		Options{Limits: Limits{PerPrincipal: 1, Total: 1, UpstreamTimeout: time.Second, ResultBytes: 1 << 16}, Launcher: memLauncher{build: build}, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("m_echo"), "c", `{}`)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got == nil || got.Capabilities == nil {
		t.Fatalf("initialize params %+v", got)
	}
	c := got.Capabilities
	if c.Sampling != nil || c.Elicitation != nil || c.RootsV2 != nil || c.Roots.ListChanged { //nolint:staticcheck // SR-5.6-2 checks that the deprecated sampling capability is absent
		t.Fatalf("client capabilities declared southbound: %+v", c)
	}
}

// TestInputRequiredResult: a backend InputRequiredResult ends the call with
// ErrInputRequired, which the edge maps to -31010 (FR-5.24).
func TestInputRequiredResult(t *testing.T) {
	reqtest.Partial(t, "FR-5.24")
	r, caps, _ := startFixture(t, 10*time.Second, "HF-25")
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_ask"), "c1", `{}`)); !errors.Is(err, ErrInputRequired) {
		t.Fatalf("got %v", err)
	}
	// The instance keeps serving.
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_echo"), "c2", `{"text":"x"}`)); err != nil {
		t.Fatal(err)
	}
}

// TestProgressRoutedWithGatewayToken: backend progress reaches the call's
// Progress function; the backend saw a Gateway-issued token, and nothing
// arrives after Call returns (FR-1.39, FR-1.40).
func TestProgressRoutedWithGatewayToken(t *testing.T) {
	reqtest.Partial(t, "FR-1.39")
	r, caps, _ := startFixture(t, 10*time.Second, "HF-07")
	var mu sync.Mutex
	var got []*mcp.ProgressNotificationParams
	returned := false
	late := false
	d := dispatch(caps, r.Resolve("a_long_task"), "c1", `{}`)
	d.Progress = func(p *mcp.ProgressNotificationParams) {
		mu.Lock()
		defer mu.Unlock()
		if returned {
			late = true
		}
		got = append(got, p)
	}
	if _, err := r.Call(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	returned = true
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || late {
		t.Fatalf("progress %d late %v", len(got), late)
	}
	for _, p := range got {
		tok, _ := p.ProgressToken.(string)
		if !strings.HasPrefix(tok, "smcp-") || !strings.Contains(p.Message, hostile.CanaryMarker) {
			t.Fatalf("progress %+v", p)
		}
	}
	// A call without Progress sends no token, so the fixture sends none.
	got = nil
	mu.Unlock()
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_long_task"), "c2", `{}`)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("progress without a token: %d", len(got))
	}
}

// TestInstanceRestartedAfterTimeout: a call that times out replaces the
// instance; later calls reach the new one (Appendix L HF-19).
func TestInstanceRestartedAfterTimeout(t *testing.T) {
	reqtest.Partial(t, "FR-4.9")
	r, caps, l := startFixture(t, 300*time.Millisecond, "HF-19")
	s := r.Servers()["a"]
	echo := func(corr string) string {
		t.Helper()
		res, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_echo"), corr, `{"text":"x"}`))
		if err != nil {
			t.Fatalf("echo: %v", err)
		}
		return res.Content[0].(*mcp.TextContent).Text
	}
	echo("e1")
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_hang"), "h1", `{}`)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
	echo("e2") // waits for the restart
	l.mu.Lock()
	first := l.procs[0]
	l.mu.Unlock()
	select {
	case <-first.done:
	default:
		t.Fatal("the timed-out instance is still running")
	}
	if s.Restarts() != 1 || l.launches.Load() != 2 {
		t.Fatalf("restarts %d launches %d", s.Restarts(), l.launches.Load())
	}
	// Concurrent timeouts on one instance restart it once.
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = r.Call(context.Background(), dispatch(caps, r.Resolve("a_hang"), "h2"+string(rune('a'+i)), `{}`))
		}(i)
	}
	wg.Wait()
	echo("e3")
	if s.Restarts() != 2 {
		t.Fatalf("restarts after concurrent timeouts: %d", s.Restarts())
	}
}

// TestInstanceRestartedAfterExit: a call that finds the instance gone fails,
// and the instance is replaced for the next call.
func TestInstanceRestartedAfterExit(t *testing.T) {
	r, caps, l := startFixture(t, 5*time.Second, "HF-19")
	l.mu.Lock()
	first := l.procs[0]
	l.mu.Unlock()
	first.Close() // the server process exits
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_echo"), "e1", `{"text":"x"}`)); err == nil {
		t.Fatal("call to an exited instance succeeded")
	}
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("a_echo"), "e2", `{"text":"x"}`)); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if r.Servers()["a"].Restarts() != 1 || l.launches.Load() != 2 {
		t.Fatalf("restarts %d launches %d", r.Servers()["a"].Restarts(), l.launches.Load())
	}
}

// TestRestartWithChangedRevisionSuspends: a relaunched instance whose tool
// list differs from the enabled revision is not used; the server is
// suspended.
func TestRestartWithChangedRevisionSuspends(t *testing.T) {
	var launches atomic.Int32
	build := func() *mcp.Server {
		s := testServer()
		if launches.Add(1) > 1 {
			mcp.AddTool(s, &mcp.Tool{Name: "extra"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{}, nil, nil
			})
		}
		return s
	}
	caps := pipeline.NewCapabilities(time.Minute)
	r, err := Start(context.Background(), []config.Server{{Alias: "m", Command: "/fake/mem"}},
		Options{Limits: Limits{PerPrincipal: 2, Total: 2, Queue: 2, UpstreamTimeout: 100 * time.Millisecond, ResultBytes: 1 << 16}, Launcher: memLauncher{build: build}, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Call(context.Background(), dispatch(caps, r.Resolve("m_sleep"), "s", `{"ms":2000}`)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.Servers()["m"] != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.Servers()["m"] != nil || r.Resolve("m_echo") != nil {
		t.Fatal("server with a changed revision kept running")
	}
}

// TestCollisionDisablesOnlyThatServer: FR-1.49 refuses to enable the
// revision and names both tools; the other servers run.
func TestCollisionDisablesOnlyThatServer(t *testing.T) {
	reqtest.Verifies(t, "FR-1.49")
	r, _, _ := startFixture(t, 10*time.Second, "HF-14", "HF-26")
	reason := r.Disabled()["a"]
	if r.Servers()["a"] != nil || !strings.Contains(reason, `"send.email"`) || !strings.Contains(reason, `"send_email"`) || !strings.Contains(reason, "FR-1.49") {
		t.Fatalf("disabled %v servers %v", r.Disabled(), r.Servers())
	}
	if r.Resolve("a_echo") != nil || r.Resolve("b_legacy") == nil {
		t.Fatalf("catalog %v", r.PublicNames())
	}
}
