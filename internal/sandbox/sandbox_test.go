package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testRuntime() config.Runtime {
	cfg, err := config.Parse([]byte(`
[admin]
username = "admin"
password_hash = "$argon2id$x"
[profile]
mode = "auto"
[runtime]
sandbox = "podman"
monitor_interval = "50ms"
`))
	if err != nil {
		panic(err)
	}
	return cfg.Runtime
}

type harness struct {
	t     *testing.T
	l     *Launcher
	dir   string
	state string
	mem   *audit.Memory
	exe   string
}

func newHarness(t *testing.T, rt config.Runtime) *harness {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	state := t.TempDir()
	rt.Podman = exe
	l, err := New(Options{Runtime: rt, StateDir: state, Log: quiet(), TerminateAfter: 300 * time.Millisecond,
		CgroupRoot: filepath.Join(dir, "cgroup"), PodmanEnv: map[string]string{"SMCP_FAKE_PODMAN": "1", "SMCP_FAKE_DIR": dir}})
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	l.SetEvidence(mem)
	t.Cleanup(l.Close)
	return &harness{t: t, l: l, dir: dir, state: state, mem: mem, exe: exe}
}

func (h *harness) spec(alias string) pipeline.ServerSpec {
	return pipeline.ServerSpec{Alias: alias, Command: h.exe, Env: map[string]string{"SMCP_FAKE_SERVER": "1", "PATH": "/usr/bin", "HOME": "/home/x"}}
}

func (h *harness) run(name string) fakeRun {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, name+".run.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	var r fakeRun
	if err := json.Unmarshal(b, &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *harness) cg(name, file, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, "cgroup", name, file), []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) kills(name string) string {
	b, _ := os.ReadFile(filepath.Join(h.dir, name+".kills"))
	return string(b)
}

// eventually waits up to d for cond.
func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func findEvent(evs []audit.Event, outcome, reason string) *audit.Event {
	for i := range evs {
		if evs[i].Outcome == outcome && (reason == "" || evs[i].ReasonCode == reason) {
			return &evs[i]
		}
	}
	return nil
}

func hasArg(args []string, a string) bool { return slices.Contains(args, a) }

// connect speaks MCP to a launched process.
func connect(t *testing.T, p pipeline.Process) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := c.Connect(ctx, &mcp.IOTransport{Reader: io.NopCloser(p), Writer: closer{p}}, nil)
	if err != nil {
		t.Fatalf("connect: %v (stderr %s)", err, p.Stderr())
	}
	return s
}

type closer struct{ p pipeline.Process }

func (c closer) Write(b []byte) (int, error) { return c.p.Write(b) }
func (c closer) Close() error                { return c.p.Close() }

func callText(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any) string {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestPodmanArgsCarryTheSandboxProfile(t *testing.T) {
	// SR-4.7-1 asks for inspection of the effective container
	// configuration; this checks the configuration the Gateway requests.
	// The Linux integration test inspects a real container.
	reqtest.Partial(t, "SR-4.7-1", "SR-4.7-2", "SR-4.5-1", "SR-4.1-2", "FR-5.9")
	exe, _ := os.Executable()
	ro, rw := t.TempDir(), t.TempDir()
	rt := testRuntime()
	srv := config.RuntimeServer{Alias: "fs", Mounts: []config.RuntimeMount{{Source: ro}, {Source: rw, Target: "/data", Write: true}}}
	ls, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "fs", Command: exe, Args: []string{"--root", "/data"},
		Env: map[string]string{"TOKEN": "s3cret-value", "PATH": "/usr/bin"}}, Egress: pipeline.EgressAttachment{Network: "none"},
		InstanceID: "0192-abcd-ef01-2345", Gateway: "gw", Rootfs: "/state/runtime/rootfs", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	args := ls.PodmanArgs()
	for _, want := range []string{"run", "--interactive", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
		"--userns=auto:size=2048", "--network=none", "--pid=private", "--ipc=private", "--uts=private", "--pull=never",
		"--memory=536870912", "--memory-swap=536870912", "--cpus=1", "--pids-limit=128", "--user=1000:1000", "--no-hosts",
		"--mount=type=bind,src=" + ro + ",dst=" + ro + ",ro,bind-propagation=rprivate",
		"--mount=type=bind,src=" + rw + ",dst=/data,rw,bind-propagation=rprivate",
		"--mount=type=bind,src=" + exe + ",dst=/smcp/bin/" + filepath.Base(exe) + ",ro,bind-propagation=rprivate",
		"--env=TOKEN", "--rootfs"} {
		if !hasArg(args, want) {
			t.Errorf("podman args lack %q\n%v", want, args)
		}
	}
	joined := strings.Join(args, " ")
	for _, bad := range []string{"--privileged", "--device", "--cap-add", "seccomp=unconfined", "--pid=host", "--network=host",
		"--ipc=host", "--uts=host", "--userns=host", "docker.sock", "podman.sock", "s3cret-value", "--env=PATH", "label=disable"} {
		if strings.Contains(joined, bad) {
			t.Errorf("podman args contain %q", bad)
		}
	}
	// Flags, then --rootfs <dir>, then the server's own argument vector.
	i := slices.Index(args, "--rootfs")
	if got := args[i+1:]; !slices.Equal(got, []string{"/state/runtime/rootfs", "/smcp/bin/" + filepath.Base(exe), "--root", "/data"}) {
		t.Fatalf("positional args = %v", got)
	}
	if !strings.HasPrefix(ls.Artifact.Digest, "sha256:") || len(ls.Artifact.Digest) != 71 {
		t.Fatalf("artifact digest %q", ls.Artifact.Digest)
	}
	if !slices.Equal(ls.EnvNames, []string{"TOKEN"}) {
		t.Fatalf("env names %v", ls.EnvNames)
	}
}

func TestBuildWithImageAndEgress(t *testing.T) {
	reqtest.Partial(t, "FR-5.37", "FR-5.9")
	rt := testRuntime()
	img := "registry.local/fs@sha256:" + strings.Repeat("a", 64)
	srv := config.RuntimeServer{Alias: "web", Image: img, Network: "egress", UserNS: "keep-id"}
	ls, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "web", Command: "/usr/local/bin/server"},
		Egress:     pipeline.EgressAttachment{Network: "smcp-egress-web", Env: map[string]string{"FETCH_BASE_URL": "http://10.89.0.1:8080"}},
		InstanceID: "i", Gateway: "gw", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	args := ls.PodmanArgs()
	if !hasArg(args, "--network=smcp-egress-web") || !hasArg(args, "--env=FETCH_BASE_URL") || !hasArg(args, "--userns=keep-id") {
		t.Fatalf("args %v", args)
	}
	if args[len(args)-2] != img || args[len(args)-1] != "/usr/local/bin/server" || ls.Artifact.Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("image positional: %v digest %s", args[len(args)-2:], ls.Artifact.Digest)
	}
	// A network the server did not ask for is refused.
	srv.Network = "none"
	if _, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "web", Command: "/usr/local/bin/server"},
		Egress: pipeline.EgressAttachment{Network: "bridge"}, StateDir: t.TempDir()}); err == nil {
		t.Fatal("unrequested network accepted")
	}
}

func TestLaunchRefusesUnsafeInput(t *testing.T) {
	reqtest.Partial(t, "SR-4.6-1", "SR-4.7-1", "SR-3.6-1")
	rt := testRuntime()
	exe, _ := os.Executable()
	state := t.TempDir()
	sock := filepath.Join(t.TempDir(), "x.sock")
	if ln, err := net.Listen("unix", sock); err == nil {
		defer ln.Close()
	}
	inside := filepath.Join(state, "keys")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	comma := filepath.Join(t.TempDir(), "a,b")
	if err := os.MkdirAll(comma, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"/", "/etc", "/proc", "/var/run", "/run/user", "relative/path", state, inside, filepath.Dir(state), sock, comma, "/does/not/exist"} {
		srv := config.RuntimeServer{Alias: "x", Mounts: []config.RuntimeMount{{Source: src}}}
		_, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "x", Command: exe}, InstanceID: "i", Rootfs: "/r", StateDir: state})
		if !errors.Is(err, ErrMountRefused) {
			t.Errorf("mount of %q: err = %v, want ErrMountRefused", src, err)
		}
	}
	ok := t.TempDir()
	for _, target := range []string{"/work", "/tmp", "/tmp/x/y", "/work/a", "/smcp/bin", "/smcp/bin/x", "/proc/x", "/dev/shm", "/run/x", "/etc/x", "/", "rel"} {
		srv := config.RuntimeServer{Alias: "x", Mounts: []config.RuntimeMount{{Source: ok, Target: target}}}
		if _, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: pipeline.ServerSpec{Alias: "x", Command: exe}, Rootfs: "/r", StateDir: state}); !errors.Is(err, ErrMountRefused) {
			t.Errorf("target %q accepted", target)
		}
	}
	for _, name := range []string{"LD_PRELOAD", "CONTAINERS_CONF", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HTTPS_PROXY"} {
		_, err := Build(BuildInput{Runtime: rt, Spec: pipeline.ServerSpec{Alias: "x", Command: exe, Env: map[string]string{name: "v"}}, Rootfs: "/r", StateDir: state})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("env %s: err = %v", name, err)
		}
	}
	for _, cmd := range []string{"npx", "/usr/bin/npx", "/usr/bin/uvx"} {
		if _, err := Build(BuildInput{Runtime: rt, Spec: pipeline.ServerSpec{Alias: "x", Command: cmd}, Rootfs: "/r", StateDir: state}); !errors.Is(err, pipeline.ErrUnpinnedLaunch) {
			t.Errorf("command %q: err = %v", cmd, err)
		}
	}
	if _, err := Build(BuildInput{Runtime: rt, Spec: pipeline.ServerSpec{Alias: "x", Command: "/no/such/binary"}, Rootfs: "/r", StateDir: state}); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("missing artifact: %v", err)
	}
}

func TestLaunchRunsServerThroughPodmanWithoutShell(t *testing.T) {
	// SR-4.8-1: launch input reaches the server as an argument vector; the
	// environment travels by name. Both launchers use exec, never a shell.
	reqtest.Verifies(t, "SR-4.8-1")
	reqtest.Partial(t, "FR-5.9", "SR-2.14-1")
	h := newHarness(t, testRuntime())
	spec := h.spec("ref")
	spec.Args = []string{"$(touch /tmp/pwned); echo `id` | sh", "a b"}
	spec.Env["API_TOKEN"] = "tok-123"
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	insts := h.l.Instances()
	if len(insts) != 1 {
		t.Fatalf("instances %d", len(insts))
	}
	name := insts[0].Container
	sess := connect(t, p)
	if got := callText(t, sess, "echo", map[string]any{"text": "hi"}); got != "hi" {
		t.Fatalf("echo = %q", got)
	}
	r := h.run(name)
	if got := r.Command[1:]; !slices.Equal(got, spec.Args) {
		t.Fatalf("server argv %v, want %v verbatim", got, spec.Args)
	}
	if strings.Contains(strings.Join(r.Argv, " "), "tok-123") {
		t.Fatal("environment value on the podman command line")
	}
	if !r.EnvSet["API_TOKEN"] || !r.EnvSet["SMCP_FAKE_SERVER"] || slices.Contains(r.EnvNames, "SMCP_FAKE_PODMAN") || slices.Contains(r.EnvNames, "PATH") {
		t.Fatalf("env names %v set %v", r.EnvNames, r.EnvSet)
	}
	if !hasArg(r.Argv, "--label") || r.Rootfs != filepath.Join(h.state, "runtime", "rootfs") {
		t.Fatalf("run %+v", r)
	}
	for _, f := range []string{"proc", "dev", "work", "etc/hosts", "etc/passwd", "smcp/bin/" + filepath.Base(h.exe)} {
		if _, err := os.Stat(filepath.Join(r.Rootfs, f)); err != nil {
			t.Errorf("root directory lacks %s", f)
		}
	}
	// The subprocess launcher passes the same vector without a shell.
	sp, err := pipeline.SubprocessLauncher{TerminateAfter: time.Second}.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	s2 := connect(t, sp)
	if got := callText(t, s2, "echo", map[string]any{"text": "ok"}); got != "ok" {
		t.Fatal(got)
	}
	s2.Close()
	if _, err := os.Stat("/tmp/pwned"); err == nil {
		t.Fatal("argument was interpreted by a shell")
	}
	sess.Close()
	eventually(t, 5*time.Second, "instance removed", func() bool { _, err := os.Stat(filepath.Join(h.dir, name+".rm")); return err == nil })
	evs := h.mem.Events()
	if e := findEvent(evs, "instance_launched", ""); e == nil || e.Origin != OriginRuntime || e.Class != EvidenceClass {
		t.Fatalf("no launch evidence: %+v", evs)
	} else if b, _ := json.Marshal(e.Detail); strings.Contains(string(b), "tok-123") {
		t.Fatal("secret value in launch evidence")
	}
	e := findEvent(evs, "instance_exited", "")
	if e == nil {
		t.Fatal("no exit evidence")
	}
	if d := e.Detail.(map[string]any); d["expected"] != true || e.ReasonCode != "" {
		t.Fatalf("exit evidence %+v", e)
	}
}

func TestBackendRegistryUsesConfinedLauncher(t *testing.T) {
	reqtest.Partial(t, "FR-5.9", "SR-4-1")
	h := newHarness(t, testRuntime())
	caps := pipeline.NewCapabilities(time.Minute)
	reg, err := backend.Start(context.Background(), []config.Server{{Alias: "probe", Command: h.exe, Env: map[string]string{"SMCP_FAKE_SERVER": "1"},
		RiskClasses: []string{"code-execution"}}}, backend.Options{Launcher: h.l, Capabilities: caps, Log: quiet(),
		Limits: backend.Limits{PerPrincipal: 1, Total: 1, UpstreamTimeout: 10 * time.Second, ResultBytes: 1 << 20}})
	if err != nil {
		t.Fatalf("a high-risk server must start under the confined launcher: %v", err)
	}
	ref := reg.Resolve("probe_echo")
	if ref == nil {
		t.Fatalf("tools %v", reg.PublicNames())
	}
	b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: "probe_echo"}
	res, err := reg.Call(context.Background(), backend.Dispatch{Principal: "p", Ref: ref, Arguments: json.RawMessage(`{"text":"via registry"}`), Capability: caps.Issue(b), Binding: b})
	if err != nil || res.Content[0].(*mcp.TextContent).Text != "via registry" {
		t.Fatalf("call: %v %+v", err, res)
	}
	reg.Close()
}

func TestMonitorKillsOnMemoryBreachWithinOneSecond(t *testing.T) {
	// The kernel enforces the cgroup limit; the monitor sees the OOM kill
	// counter and kills the instance. Measured from the counter change.
	reqtest.Partial(t, "FR-5.35", "FR-5.33", "SR-4.7-2")
	h := newHarness(t, testRuntime())
	p, err := h.l.Launch(context.Background(), h.spec("mem"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	name := h.l.Instances()[0].Container
	eventually(t, 3*time.Second, "running", func() bool { return h.l.Instances()[0].State == StateRunning })
	start := time.Now()
	h.cg(name, "memory.events", "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n")
	eventually(t, time.Second, "kill within 1 s", func() bool { return strings.Contains(h.kills(name), "KILL") })
	if el := time.Since(start); el > time.Second {
		t.Fatalf("containment took %v", el)
	}
	eventually(t, 3*time.Second, "breach evidence", func() bool { return findEvent(h.mem.Events(), "limit_breach", ReasonMemoryLimit) != nil })
	e := findEvent(h.mem.Events(), "limit_breach", ReasonMemoryLimit)
	if d := e.Detail.(map[string]any); d["action"] != ActionKill || e.Origin != OriginMonitor {
		t.Fatalf("evidence %+v", e)
	}
	eventually(t, 3*time.Second, "exit evidence", func() bool { return findEvent(h.mem.Events(), "instance_exited", "") != nil })
	v := h.l.Instances()[0]
	if v.State != StateKilled || v.KillReason != ReasonMemoryLimit || v.Deviations != 1 {
		t.Fatalf("view %+v", v)
	}
}

func TestMonitorKillsOnPidsBreach(t *testing.T) {
	reqtest.Partial(t, "FR-5.35", "SR-4.7-2")
	h := newHarness(t, testRuntime())
	p, err := h.l.Launch(context.Background(), h.spec("pids"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	name := h.l.Instances()[0].Container
	eventually(t, 3*time.Second, "running", func() bool { return h.l.Instances()[0].State == StateRunning })
	h.cg(name, "pids.events", "max 2\n")
	eventually(t, time.Second, "kill", func() bool { return strings.Contains(h.kills(name), "KILL") })
	eventually(t, 3*time.Second, "evidence", func() bool { return findEvent(h.mem.Events(), "limit_breach", ReasonPidsLimit) != nil })
}

func TestMonitorUndeclaredProcessAlertsOrKills(t *testing.T) {
	reqtest.Partial(t, "FR-5.33", "FR-5.34", "FR-5.35")
	for _, rule := range []string{ActionAlert, ActionKill} {
		t.Run(rule, func(t *testing.T) {
			rt := testRuntime()
			rt.Servers = []config.RuntimeServer{{Alias: "sp", OnDeviation: rule}}
			h := newHarness(t, rt)
			p, err := h.l.Launch(context.Background(), h.spec("sp"))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			sess := connect(t, p)
			name := h.l.Instances()[0].Container
			eventually(t, 3*time.Second, "first sample", func() bool { return findEvent(h.mem.Events(), "process_created", "") != nil })
			main := h.l.Instances()[0]
			_ = main
			pid, _ := os.ReadFile(filepath.Join(h.dir, name+".pid"))
			h.cg(name, "cgroup.procs", strings.TrimSpace(string(pid))+"\n999999\n")
			eventually(t, 2*time.Second, "deviation", func() bool { return findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess) != nil })
			e := findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess)
			if e.Detail.(map[string]any)["action"] != rule {
				t.Fatalf("action %v", e.Detail)
			}
			if rule == ActionAlert {
				if got := callText(t, sess, "echo", map[string]any{"text": "alive"}); got != "alive" || strings.Contains(h.kills(name), "KILL") {
					t.Fatal("alert must not stop the instance")
				}
			} else {
				eventually(t, time.Second, "kill", func() bool { return strings.Contains(h.kills(name), "KILL") })
			}
		})
	}
}

func TestMonitorExecEventIsDeviation(t *testing.T) {
	reqtest.Partial(t, "FR-5.33", "FR-5.34")
	rt := testRuntime()
	rt.Servers = []config.RuntimeServer{{Alias: "ex", OnDeviation: ActionKill}}
	h := newHarness(t, rt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.l.Start(ctx)
	p, err := h.l.Launch(context.Background(), h.spec("ex"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	in := h.l.Instances()[0]
	line, _ := json.Marshal(PodmanEvent{ID: "x", Name: in.Container, Status: "exec", Type: "container",
		Attributes: map[string]string{LabelGateway: h.l.GatewayID(), LabelInstance: in.ID}})
	// An event of another Gateway is ignored.
	other, _ := json.Marshal(PodmanEvent{Name: in.Container, Status: "exec", Attributes: map[string]string{LabelGateway: "other", LabelInstance: in.ID}})
	if err := os.WriteFile(filepath.Join(h.dir, "events.jsonl"), append(append(other, '\n'), append(line, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "exec deviation", func() bool { return findEvent(h.mem.Events(), "deviation", ReasonExecIntoInstance) != nil })
	eventually(t, time.Second, "kill", func() bool { return strings.Contains(h.kills(in.Container), "KILL") })
	if n := strings.Count(h.kills(in.Container), "KILL"); n != 1 {
		t.Fatalf("killed %d times", n)
	}
}

func TestUnexpectedExitIsRecorded(t *testing.T) {
	// FR-5.12 also asks for restart on next use and suspension after three
	// exits in five minutes; those belong to the registry and are not built.
	reqtest.Partial(t, "FR-5.12")
	h := newHarness(t, testRuntime())
	p, err := h.l.Launch(context.Background(), h.spec("crash"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	name := h.l.Instances()[0].Container
	if err := os.WriteFile(filepath.Join(h.dir, name+".exit"), []byte("137"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, name+".oom"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pid, _ := os.ReadFile(filepath.Join(h.dir, name+".pid"))
	pr, _ := os.FindProcess(atoi(string(pid)))
	_ = pr.Kill()
	eventually(t, 3*time.Second, "exit evidence", func() bool { return findEvent(h.mem.Events(), "instance_exited", ReasonMemoryLimit) != nil })
	e := findEvent(h.mem.Events(), "instance_exited", ReasonMemoryLimit)
	d := e.Detail.(map[string]any)
	if d["expected"] != false || d["exit_code"] != 137 || d["oom_killed"] != true {
		t.Fatalf("detail %+v", d)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestShutdownSequenceEscalates(t *testing.T) {
	// FR-5.27 at a scaled interval (300 ms instead of 5 s); the default is
	// checked below.
	reqtest.Partial(t, "FR-5.27")
	h := newHarness(t, testRuntime())
	spec := h.spec("stub")
	spec.Env["SMCP_FAKE_SERVER"] = "ignore-eof"
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	name := h.l.Instances()[0].Container
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	el := time.Since(start)
	k := h.kills(name)
	if !strings.Contains(k, "TERM") || !strings.Contains(k, "KILL") || strings.Index(k, "TERM") > strings.Index(k, "KILL") {
		t.Fatalf("kill sequence %q", k)
	}
	// Each fake podman invocation starts the test binary, which adds time.
	if el < 600*time.Millisecond || el > 15*time.Second {
		t.Fatalf("shutdown took %v; want two 300 ms waits before SIGKILL", el)
	}
	l, _ := New(Options{Runtime: testRuntime(), StateDir: t.TempDir(), Log: quiet()})
	if l != nil && l.o.TerminateAfter != 5*time.Second {
		t.Fatalf("default wait %v", l.o.TerminateAfter)
	}
}

func TestReapRemovesOtherGatewaysContainers(t *testing.T) {
	h := newHarness(t, testRuntime())
	ps := "smcp-old-1 gw-old\nsmcp-mine-2 " + h.l.GatewayID() + "\n"
	if err := os.WriteFile(filepath.Join(h.dir, "ps.txt"), []byte(ps), 0o600); err != nil {
		t.Fatal(err)
	}
	h.l.Reap(context.Background())
	if _, err := os.Stat(filepath.Join(h.dir, "smcp-old-1.rm")); err != nil {
		t.Fatal("leftover container not removed")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "smcp-mine-2.rm")); err == nil {
		t.Fatal("own container removed")
	}
}

type recordingEgress struct {
	released int
	spec     pipeline.ServerSpec
}

func (r *recordingEgress) Attach(_ context.Context, spec pipeline.ServerSpec, _ string) (pipeline.EgressAttachment, error) {
	r.spec = spec
	return pipeline.EgressAttachment{Network: "smcp-egress", Env: map[string]string{"FETCH_URL": "http://10.0.0.1:1"}, Release: func() { r.released++ }}, nil
}

func TestEgressAttacherIsAskedOnlyWhenGranted(t *testing.T) {
	reqtest.Partial(t, "FR-5.37", "SR-4.5-1")
	rt := testRuntime()
	rt.Servers = []config.RuntimeServer{{Alias: "web", Network: "egress"}}
	h := newHarness(t, rt)
	eg := &recordingEgress{}
	h.l.o.Egress = eg
	p, err := h.l.Launch(context.Background(), h.spec("web"))
	if err != nil {
		t.Fatal(err)
	}
	connect(t, p)
	name := h.l.Instances()[0].Container
	r := h.run(name)
	if !hasArg(r.Argv, "--network=smcp-egress") || !r.EnvSet["FETCH_URL"] {
		t.Fatalf("run %+v", r)
	}
	p.Close()
	if eg.released != 1 {
		t.Fatalf("released %d", eg.released)
	}
	p2, err := h.l.Launch(context.Background(), h.spec("plain"))
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	connect(t, p2)
	if r := h.run(h.l.Instances()[1].Container); !hasArg(r.Argv, "--network=none") || eg.spec.Alias != "web" {
		t.Fatalf("server without egress grant: %v", r.Argv)
	}
}

func TestLazyRecorderBuffersUntilAttached(t *testing.T) {
	lr := newLazyRecorder(quiet())
	_ = lr.write(audit.Event{Outcome: "a"}, false)
	_ = lr.write(audit.Event{Outcome: "b"}, true)
	mem := &audit.Memory{}
	lr.attach(mem)
	_ = lr.write(audit.Event{Outcome: "c"}, false)
	evs := mem.Events()
	if len(evs) != 3 || evs[0].Outcome != "a" || evs[2].Outcome != "c" {
		t.Fatalf("%+v", evs)
	}
	lr2 := newLazyRecorder(quiet())
	for range maxPending + 5 {
		_ = lr2.write(audit.Event{Outcome: "x"}, false)
	}
	mem2 := &audit.Memory{}
	lr2.attach(mem2)
	if e := findEvent(mem2.Events(), "evidence_dropped", ""); e == nil || e.Detail.(map[string]any)["events"] != 5 {
		t.Fatal("dropped evidence not reported")
	}
}

func TestReadCgroup(t *testing.T) {
	reqtest.Partial(t, "FR-5.33")
	dir := t.TempDir()
	sub := filepath.Join(dir, "container")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"memory.current": "100\n", "memory.peak": "200\n", "pids.current": "3", "pids.peak": "4",
		"memory.events": "oom 2\noom_kill 1\n", "pids.events": "max 7\n", "cpu.stat": "usage_usec 99\n", "cgroup.procs": "10\n"} {
		_ = os.WriteFile(filepath.Join(dir, f), []byte(v), 0o600)
	}
	_ = os.WriteFile(filepath.Join(sub, "cgroup.procs"), []byte("12\n11\n"), 0o600)
	s, err := ReadCgroup(dir, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if s.MemoryCurrent != 100 || s.MemoryPeak != 200 || s.Pids != 3 || s.PidsPeak != 4 || s.OOMEvents != 2 || s.OOMKills != 1 ||
		s.PidsMaxEvents != 7 || s.CPUUsageUsec != 99 || !slices.Equal(s.Procs, []int{10, 11, 12}) {
		t.Fatalf("%+v", s)
	}
	if _, err := ReadCgroup(filepath.Join(dir, "gone"), time.Now()); err == nil {
		t.Fatal("missing cgroup read")
	}
}
