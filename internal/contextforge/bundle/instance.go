package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Instance states reported to G-15 and the health monitor (FR-22.41).
const (
	StateStopped   = "stopped"
	StateStarting  = "starting"
	StateHealthy   = "healthy"
	StateUnhealthy = "unhealthy"
)

// Defaults of the health checks (FR-22.30): the CP-47 health wait, the
// check interval while running and the failures before a restart.
const (
	DefaultHealthWait     = 60 * time.Second
	DefaultHealthInterval = 10 * time.Second
	DefaultFailures       = 3
)

// Engine is the container engine binary: docker or podman.
type Engine struct {
	Path string
	// Podman selects podman's flags (rootless user namespace, :U volume
	// ownership); otherwise Docker's.
	Podman bool
}

// Options configure an Instance.
type Options struct {
	Engine Engine
	// Image is the digest-pinned image reference (FR-22.18).
	Image string
	// Name is the container name and the prefix of its volume.
	Name     string
	Settings Settings
	// Credentials returns the instance credentials from the vault at each
	// start (FR-22.28). They reach the engine only through its process
	// environment, never a file or the argument vector.
	Credentials func() (Credentials, error)
	// MemoryMiB, CPUs and Pids are the CP-24 limits doubled (FR-22.24);
	// defaults 1024, 2 and 256.
	MemoryMiB int
	CPUs      float64
	Pids      int

	HealthWait     time.Duration
	HealthInterval time.Duration
	Failures       int
	// OnState is called on each state change (health evidence, G-15).
	OnState func(state, detail string)
	Log     *slog.Logger
	// Enforced runs the instance under the Enforced containment
	// (network.go, FR-22.24): rootless Podman only.
	Enforced bool
}

// Status is the instance's state for G-15 and smcpctl.
type Status struct {
	State     string    `json:"state"`
	Detail    string    `json:"detail,omitempty"`
	Port      int       `json:"port,omitempty"`
	Image     string    `json:"image"`
	StartedAt time.Time `json:"started_at,omitzero"`
	Restarts  int       `json:"restarts"`
}

// Instance is the bundled ContextForge container.
type Instance struct {
	o    Options
	http *http.Client
	// exec runs the engine; tests replace it.
	exec      func(ctx context.Context, vals map[string]string, args ...string) (string, error)
	execStdin func(ctx context.Context, stdin string, args ...string) (string, error)

	mu          sync.Mutex
	access      HostAccess
	egressAllow netip.AddrPort
	st          Status
	creds       Credentials
	cancel      context.CancelFunc
	stopped     chan struct{}
}

// New prepares an Instance; nothing runs until Start.
func New(o Options) (*Instance, error) {
	if o.Engine.Path == "" || o.Image == "" || o.Name == "" || o.Credentials == nil {
		return nil, errors.New("bundle: engine, image, name and credentials are required")
	}
	if !strings.Contains(o.Image, "@sha256:") {
		return nil, fmt.Errorf("bundle: image %q is not pinned by digest", o.Image)
	}
	if o.Enforced && !o.Engine.Podman {
		return nil, errors.New("bundle: the Enforced containment runs the instance with rootless Podman only")
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
	i := &Instance{o: o, http: &http.Client{Timeout: 5 * time.Second}, st: Status{State: StateStopped, Image: o.Image}}
	i.exec = i.runEngine
	i.execStdin = i.runEngineStdin
	return i, nil
}

// Status returns the current state.
func (i *Instance) Status() Status {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.st
}

// BaseURL is the loopback URL of the listener ("" while stopped).
func (i *Instance) BaseURL() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.st.Port == 0 {
		return ""
	}
	return "http://127.0.0.1:" + strconv.Itoa(i.st.Port)
}

// Healthy reports whether the instance answers /health.
func (i *Instance) Healthy() bool { return i.Status().State == StateHealthy }

// AdminToken mints an administrator token for the admin API (I-43).
func (i *Instance) AdminToken(ttl time.Duration) (string, error) {
	i.mu.Lock()
	c := i.creds
	i.mu.Unlock()
	if c == nil {
		return "", errors.New("bundle: the instance is not running")
	}
	return AdminToken(c, time.Now(), ttl)
}

func (i *Instance) setState(state, detail string) {
	i.mu.Lock()
	changed := i.st.State != state
	i.st.State, i.st.Detail = state, detail
	i.mu.Unlock()
	if changed && i.o.OnState != nil {
		i.o.OnState(state, detail)
	}
}

// Start checks the configuration and credentials, starts the container on
// a fresh loopback port and supervises it until Stop: the instance is
// "starting" until its first /health answer, is restarted when that does
// not come within the health wait, and after Failures consecutive failed
// checks while running (FR-22.30).
func (i *Instance) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.cancel != nil {
		i.mu.Unlock()
		return nil
	}
	i.mu.Unlock()
	env := Environment(i.o.Settings)
	if err := CheckEnvironment(env, i.o.Settings.Limits); err != nil {
		return err
	}
	creds, err := i.o.Credentials()
	if err != nil {
		return err
	}
	if err := creds.Check(); err != nil {
		return err
	}
	if err := i.prepareVolume(ctx); err != nil {
		return err
	}
	if err := i.run(ctx, env, creds); err != nil {
		return err
	}
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	i.mu.Lock()
	i.creds, i.cancel, i.stopped = creds, cancel, make(chan struct{})
	stopped := i.stopped
	i.mu.Unlock()
	go func() {
		defer close(stopped)
		i.supervise(sctx, env, creds)
	}()
	return nil
}

// Stop stops supervision and removes the container; the volume (D-16)
// stays.
func (i *Instance) Stop(ctx context.Context) error {
	i.mu.Lock()
	cancel, stopped := i.cancel, i.stopped
	i.cancel = nil
	i.mu.Unlock()
	if cancel != nil {
		cancel()
		<-stopped
	}
	err := i.remove(ctx)
	i.mu.Lock()
	i.st.Port, i.creds = 0, nil
	i.mu.Unlock()
	i.setState(StateStopped, "")
	return err
}

// RemoveVolume deletes D-16 (uninstall, FR-22.32). The instance must be
// stopped.
func (i *Instance) RemoveVolume(ctx context.Context) error {
	out, err := i.engine(ctx, nil, "volume", "rm", "-f", i.volume())
	if err != nil {
		return fmt.Errorf("remove volume: %w: %s", err, out)
	}
	return nil
}

func (i *Instance) volume() string { return i.o.Name + "-data" }

// RemoveImage removes the pinned image from the engine (uninstall,
// FR-22.32). The instance must be stopped.
func (i *Instance) RemoveImage(ctx context.Context) error {
	out, err := i.engine(ctx, nil, "rmi", i.o.Image)
	if err != nil && !strings.Contains(strings.ToLower(out), "no such image") {
		return fmt.Errorf("remove image: %w: %s", err, out)
	}
	return nil
}

// prepareVolume creates the instance's volume and, for Docker, gives it to
// the image's user once (podman does that with the :U option).
func (i *Instance) prepareVolume(ctx context.Context) error {
	if _, err := i.engine(ctx, nil, "volume", "inspect", i.volume()); err == nil {
		return nil
	}
	if out, err := i.engine(ctx, nil, "volume", "create", i.volume()); err != nil {
		return fmt.Errorf("create volume: %w: %s", err, out)
	}
	if i.o.Engine.Podman {
		return nil
	}
	out, err := i.engine(ctx, nil, "run", "--rm", "--network=none", "--user", "0", "--cap-drop", "ALL", "--cap-add", "CHOWN",
		"--entrypoint", "/bin/chown", "-v", i.volume()+":/app/data", i.o.Image, "10001:10001", "/app/data")
	if err != nil {
		return fmt.Errorf("prepare volume: %w: %s", err, out)
	}
	return nil
}

// run starts the container. Every configuration key and credential is
// passed as a bare "-e KEY" whose value the engine reads from its own
// environment, so no credential is on a command line or in a file.
func (i *Instance) run(ctx context.Context, env map[string]string, creds Credentials) error {
	_ = i.remove(ctx)
	port, err := freeLoopbackPort()
	if err != nil {
		return err
	}
	vol := i.volume() + ":/app/data"
	if i.o.Engine.Podman {
		vol += ":U"
	}
	args := []string{"--name", i.o.Name,
		"-p", "127.0.0.1:" + strconv.Itoa(port) + ":" + strconv.Itoa(ContainerPort),
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", strconv.Itoa(i.o.MemoryMiB) + "m", "--cpus", strconv.FormatFloat(i.o.CPUs, 'f', -1, 64),
		"--pids-limit", strconv.Itoa(i.o.Pids), "-v", vol, "--label", "smcp.component=contextforge"}
	args = append(args, i.networkArgs()...)
	vals := map[string]string{}
	for k, v := range env {
		vals[k] = v
	}
	for k, v := range creds {
		vals[k] = v
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k)
	}
	args = append(args, i.o.Image)
	if i.o.Enforced {
		if err := i.startEnforced(ctx, vals, args); err != nil {
			return errors.New(redactOutput(err.Error(), creds))
		}
	} else if out, err := i.engine(ctx, vals, append([]string{"run", "-d"}, args...)...); err != nil {
		return fmt.Errorf("start bundled ContextForge: %w: %s", err, redactOutput(out, creds))
	}
	i.mu.Lock()
	i.st.Port, i.st.StartedAt = port, time.Now()
	i.mu.Unlock()
	i.setState(StateStarting, "")
	return nil
}

func (i *Instance) remove(ctx context.Context) error {
	out, err := i.engine(ctx, nil, "rm", "-f", i.o.Name)
	if err != nil && !strings.Contains(strings.ToLower(out), "no such container") {
		return fmt.Errorf("remove container: %w: %s", err, out)
	}
	return nil
}

// supervise waits for the first healthy answer, then checks health every
// interval, restarting the container as FR-22.30 states.
func (i *Instance) supervise(ctx context.Context, env map[string]string, creds Credentials) {
	for {
		if !i.waitHealthy(ctx) {
			if ctx.Err() != nil {
				return
			}
			i.restart(ctx, env, creds, "no /health answer within "+i.o.HealthWait.String())
			continue
		}
		i.setState(StateHealthy, "")
		fails := 0
		t := time.NewTicker(i.o.HealthInterval)
		for fails < i.o.Failures {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			if i.check(ctx) {
				fails = 0
			} else {
				fails++
			}
		}
		t.Stop()
		i.setState(StateUnhealthy, fmt.Sprintf("%d consecutive failed health checks", fails))
		i.restart(ctx, env, creds, "health checks failed")
	}
}

func (i *Instance) restart(ctx context.Context, env map[string]string, creds Credentials, why string) {
	i.o.Log.Warn("restarting bundled ContextForge", "reason", why)
	i.mu.Lock()
	i.st.Restarts++
	i.mu.Unlock()
	if err := i.run(ctx, env, creds); err != nil {
		i.setState(StateUnhealthy, err.Error())
		select {
		case <-ctx.Done():
		case <-time.After(i.o.HealthInterval):
		}
	}
}

func (i *Instance) waitHealthy(ctx context.Context) bool {
	deadline := time.Now().Add(i.o.HealthWait)
	for time.Now().Before(deadline) {
		if i.check(ctx) {
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

// check asks /health, which ContextForge answers without authentication.
func (i *Instance) check(ctx context.Context) bool {
	base := i.BaseURL()
	if base == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := i.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode == http.StatusOK
}

func (i *Instance) engine(ctx context.Context, vals map[string]string, args ...string) (string, error) {
	return i.exec(ctx, vals, args...)
}

// runEngine runs the container engine with a minimal environment plus
// vals.
func (i *Instance) runEngine(ctx context.Context, vals map[string]string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, i.o.Engine.Path, args...) //nolint:gosec // G204: the configured engine binary; arguments built here
	env := []string{}
	for _, k := range []string{"PATH", "HOME", "XDG_RUNTIME_DIR", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "CONTAINER_HOST", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range vals {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// redactOutput removes credential values from engine output before it is
// put into an error or a log.
func redactOutput(out string, creds Credentials) string {
	for _, v := range creds {
		if v != "" {
			out = strings.ReplaceAll(out, v, "[redacted]")
		}
	}
	return out
}

func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// FindEngine returns podman or docker from PATH, preferring podman.
func FindEngine() (Engine, error) {
	if p, err := exec.LookPath("podman"); err == nil {
		return Engine{Path: p, Podman: true}, nil
	}
	if p, err := exec.LookPath("docker"); err == nil {
		return Engine{Path: p}, nil
	}
	return Engine{}, errors.New("bundle: neither podman nor docker is installed")
}
