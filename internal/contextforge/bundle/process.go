package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// The managed-process form of the bundled instance (SRS FR-22.25): on
// Windows, and where no container engine is installed, ContextForge runs
// as a child process of the Gateway with an environment built only from
// the generated configuration and the vault's credentials, a private
// working directory holding D-16, a listener on 127.0.0.1 on a port chosen
// at each start, and the CP-24 limits doubled where the operating system
// applies them: on Windows in its own Job Object with kill-on-close
// (winsandbox.StartManaged). It is unconfined, and the health monitor
// reports contextforge_unconfined while it runs.
//
// The interpreter is the operator's virtual environment with ContextForge
// installed ([contextforge] python): the wheel set of FR-22.20, verified
// against the release lock, is not built yet.

// ManagedProc is a running managed process.
type ManagedProc interface {
	Done() <-chan struct{}
	Stop(grace time.Duration) error
}

// ProcessOptions configure a Process.
type ProcessOptions struct {
	// Python is the interpreter of the virtual environment that holds
	// ContextForge.
	Python string
	// Dir is the private working directory; D-16 is Dir/data.
	Dir         string
	Settings    Settings
	Credentials func() (Credentials, error)
	// MemoryMiB, CPUs and Pids are the CP-24 limits doubled; defaults
	// 1024, 2 and 256.
	MemoryMiB int
	CPUs      float64
	Pids      int
	// Start starts the process; default winsandbox.StartManaged on
	// Windows and a plain child process elsewhere.
	Start          func(winsandbox.ManagedSpec) (ManagedProc, error)
	HealthWait     time.Duration
	HealthInterval time.Duration
	Failures       int
	OnState        func(state, detail string)
	Log            *slog.Logger
}

// Process is the managed-process form of the bundled instance. It
// implements the Connector's Runner.
type Process struct {
	o    ProcessOptions
	http *http.Client

	mu      sync.Mutex
	st      Status
	creds   Credentials
	proc    ManagedProc
	cancel  context.CancelFunc
	stopped chan struct{}
	env     []string
}

// NewProcess prepares a Process; nothing runs until Start.
func NewProcess(o ProcessOptions) (*Process, error) {
	if o.Python == "" || !filepath.IsAbs(o.Python) || o.Dir == "" || o.Credentials == nil {
		return nil, errors.New("bundle: the managed process needs an absolute interpreter path, a working directory and credentials")
	}
	if o.MemoryMiB == 0 {
		o.MemoryMiB = 1024
	}
	if o.CPUs == 0 {
		o.CPUs = 2
	}
	if o.Pids == 0 {
		o.Pids = 256
	}
	if o.HealthWait == 0 {
		o.HealthWait = DefaultHealthWait
	}
	if o.HealthInterval == 0 {
		o.HealthInterval = DefaultHealthInterval
	}
	if o.Failures == 0 {
		o.Failures = DefaultFailures
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Start == nil {
		o.Start = startManaged
	}
	return &Process{o: o, http: &http.Client{Timeout: 5 * time.Second}, st: Status{State: StateStopped, Image: "managed-process"}}, nil
}

func startManaged(s winsandbox.ManagedSpec) (ManagedProc, error) {
	if runtime.GOOS == "windows" {
		m, err := winsandbox.StartManaged(s)
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	return startChild(s)
}

// Status implements Runner.
func (p *Process) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st
}

// BaseURL implements Runner.
func (p *Process) BaseURL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st.Port == 0 {
		return ""
	}
	return "http://127.0.0.1:" + strconv.Itoa(p.st.Port)
}

// Healthy implements Runner.
func (p *Process) Healthy() bool { return p.Status().State == StateHealthy }

// AdminToken implements Runner.
func (p *Process) AdminToken(ttl time.Duration) (string, error) {
	p.mu.Lock()
	c := p.creds
	p.mu.Unlock()
	if c == nil {
		return "", errors.New("bundle: the instance is not running")
	}
	return AdminToken(c, time.Now(), ttl)
}

// HostAccess implements Runner: the process shares the host's loopback.
func (p *Process) HostAccess(context.Context) (HostAccess, error) {
	return HostAccess{Listen: netip.MustParseAddr("127.0.0.1")}, nil
}

// SetSSRFAllowed implements Runner.
func (p *Process) SetSSRFAllowed(nets []string) {
	p.mu.Lock()
	p.o.Settings.SSRFAllowed = append([]string(nil), nets...)
	p.mu.Unlock()
}

// SetEgressAllow implements Runner; the managed process has no network
// namespace to confine.
func (p *Process) SetEgressAllow(netip.AddrPort) {}

// RemoveImage implements Runner; there is no image.
func (p *Process) RemoveImage(context.Context) error { return nil }

// RemoveVolume implements Runner: it removes D-16.
func (p *Process) RemoveVolume(context.Context) error {
	return os.RemoveAll(filepath.Join(p.o.Dir, "data"))
}

// Environment returns the process environment of a start on port: the
// generated configuration with the listener on loopback and D-16 in the
// working directory, the credentials, and, on Windows, SYSTEMROOT, which
// the interpreter's networking needs. Nothing else of the Gateway's
// environment is passed (SR-2.14-1).
func (p *Process) Environment(port int, creds Credentials) []string {
	p.mu.Lock()
	s := p.o.Settings
	p.mu.Unlock()
	env := Environment(s)
	env["HOST"] = "127.0.0.1"
	env["PORT"] = strconv.Itoa(port)
	env["DATABASE_URL"] = "sqlite:///" + filepath.ToSlash(filepath.Join(p.o.Dir, "data", "mcp.db"))
	for k, v := range creds {
		env[k] = v
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("SYSTEMROOT"); v != "" {
			env["SYSTEMROOT"] = v
		}
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// Start implements Runner: it checks the configuration and credentials,
// starts the process and supervises it as the container form is
// supervised (FR-22.30).
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.cancel != nil {
		p.mu.Unlock()
		return nil
	}
	s := p.o.Settings
	p.mu.Unlock()
	if err := CheckEnvironment(Environment(s), s.Limits); err != nil {
		return err
	}
	creds, err := p.o.Credentials()
	if err != nil {
		return err
	}
	if err := creds.Check(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(p.o.Dir, "data"), 0o700); err != nil {
		return err
	}
	if err := p.run(creds); err != nil {
		return err
	}
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p.mu.Lock()
	p.creds, p.cancel, p.stopped = creds, cancel, make(chan struct{})
	stopped := p.stopped
	p.mu.Unlock()
	go func() {
		defer close(stopped)
		p.supervise(sctx, creds)
	}()
	return nil
}

// Spec returns the managed-process specification of a start on port.
func (p *Process) Spec(port int, creds Credentials) winsandbox.ManagedSpec {
	return winsandbox.ManagedSpec{Path: p.o.Python, Args: []string{"-m", "uvicorn", "mcpgateway.main:app", "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--workers", "1"},
		Env: p.Environment(port, creds), Dir: p.o.Dir,
		Limits: winsandbox.Limits{MemoryBytes: int64(p.o.MemoryMiB) << 20, CPUs: p.o.CPUs, Processes: p.o.Pids}}
}

func (p *Process) run(creds Credentials) error {
	p.kill()
	port, err := freeLoopbackPort()
	if err != nil {
		return err
	}
	spec := p.Spec(port, creds)
	proc, err := p.o.Start(spec)
	if err != nil {
		return fmt.Errorf("start the bundled ContextForge process: %w", err)
	}
	p.mu.Lock()
	p.proc, p.st.Port, p.st.StartedAt, p.env = proc, port, time.Now(), spec.Env
	p.mu.Unlock()
	p.setState(StateStarting, "")
	return nil
}

func (p *Process) kill() {
	p.mu.Lock()
	proc := p.proc
	p.proc = nil
	p.mu.Unlock()
	if proc != nil {
		_ = proc.Stop(5 * time.Second)
	}
}

// Stop implements Runner.
func (p *Process) Stop(context.Context) error {
	p.mu.Lock()
	cancel, stopped := p.cancel, p.stopped
	p.cancel = nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
		<-stopped
	}
	p.kill()
	p.mu.Lock()
	p.st.Port, p.creds = 0, nil
	p.mu.Unlock()
	p.setState(StateStopped, "")
	return nil
}

func (p *Process) setState(state, detail string) {
	p.mu.Lock()
	changed := p.st.State != state
	p.st.State, p.st.Detail = state, detail
	p.mu.Unlock()
	if changed && p.o.OnState != nil {
		p.o.OnState(state, detail)
	}
}

func (p *Process) supervise(ctx context.Context, creds Credentials) {
	for {
		if !p.waitHealthy(ctx) {
			if ctx.Err() != nil {
				return
			}
			p.restart(ctx, creds, "no /health answer within "+p.o.HealthWait.String())
			continue
		}
		p.setState(StateHealthy, "")
		fails := 0
		t := time.NewTicker(p.o.HealthInterval)
		for fails < p.o.Failures {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			if p.check(ctx) {
				fails = 0
			} else {
				fails++
			}
		}
		t.Stop()
		p.setState(StateUnhealthy, fmt.Sprintf("%d consecutive failed health checks", fails))
		p.restart(ctx, creds, "health checks failed")
	}
}

func (p *Process) restart(ctx context.Context, creds Credentials, why string) {
	p.o.Log.Warn("restarting the bundled ContextForge process", "reason", why)
	p.mu.Lock()
	p.st.Restarts++
	p.mu.Unlock()
	if err := p.run(creds); err != nil {
		p.setState(StateUnhealthy, err.Error())
		select {
		case <-ctx.Done():
		case <-time.After(p.o.HealthInterval):
		}
	}
}

func (p *Process) waitHealthy(ctx context.Context) bool {
	deadline := time.Now().Add(p.o.HealthWait)
	for time.Now().Before(deadline) {
		if p.check(ctx) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false
}

func (p *Process) check(ctx context.Context) bool {
	base := p.BaseURL()
	if base == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode == http.StatusOK
}

// Running reports whether the process is started (the health check of
// winsandbox.ContextForgeUnconfinedCheck).
func (p *Process) Running() bool { return p.Status().State != StateStopped }
