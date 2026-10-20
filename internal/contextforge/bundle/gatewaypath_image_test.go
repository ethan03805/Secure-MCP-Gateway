package bundle

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// provisionedImage is the pinned image started as the Connector starts
// it (the generated configuration, CheckEnvironment, a loopback port) with
// one hosted package provisioned against a fixture on the host.
type provisionedImage struct {
	eng   Engine
	img   string
	name  string
	in    *Instance
	admin *Admin
	pkg   *Provisioned
	up    *upstream
	host  cftest.Host
}

func startProvisionedImage(t *testing.T, name string) *provisionedImage {
	t.Helper()
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge image")
	}
	eng, err := FindEngine()
	if err != nil {
		t.Skip(err)
	}
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	h := cftest.FixtureHost(t, eng.Path, img)
	creds, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	in, err := New(Options{Engine: eng, Image: img, Name: name,
		Settings:    Settings{SSRFAllowed: h.Nets, Limits: Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}},
		Credentials: func() (Credentials, error) { return creds, nil }, HealthWait: 120 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = in.Stop(ctx); _ = in.RemoveVolume(ctx) })
	if err := in.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for !in.Healthy() {
		if time.Now().After(deadline) {
			t.Fatal("not healthy")
		}
		time.Sleep(200 * time.Millisecond)
	}
	a := &Admin{Base: in.BaseURL(), AdminToken: func() (string, error) { return in.AdminToken(5 * time.Minute) }}
	u := newUpstream(t, h, "A")
	pw, _ := NewCredential()
	p, err := a.Provision(ctx, PackageSpec{Slug: "smcp-pkg-a", URL: h.URL(u.port)}, pw)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(p.Tools) == 0 || p.Token == "" {
		t.Fatalf("provisioned %+v", p)
	}
	return &provisionedImage{eng: eng, img: img, name: name, in: in, admin: a, pkg: p, up: u, host: h}
}

// sidecar runs a command of the pinned image in the instance's network
// namespace only: it sees the instance's sockets, while its processes stay
// out of the instance's process list.
func (pi *provisionedImage) sidecar(args ...string) *exec.Cmd {
	full := append([]string{"run", "--rm", "--network", "container:" + pi.name, "--entrypoint", "/bin/sh", pi.img, "-c"}, args...)
	return exec.Command(pi.eng.Path, full...)
}

// socket is one line of /proc/net/tcp, /proc/net/tcp6 or /proc/net/udp.
type socket struct {
	local, remote netip.AddrPort
	state         string
}

const (
	tcpEstablished = "01"
	tcpSynSent     = "02"
	tcpListen      = "0A"
)

// parseProcNet reads the socket lines of /proc/net files; other lines are
// skipped.
func parseProcNet(out string) []socket {
	var socks []socket
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		l, err1 := procAddr(f[1])
		r, err2 := procAddr(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		socks = append(socks, socket{local: l, remote: r, state: f[3]})
	}
	return socks
}

// procAddr decodes "0100007F:115C" (IPv4) or the 32-digit IPv6 form: the
// address in host-order 32-bit words, the port in network order.
func procAddr(s string) (netip.AddrPort, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("no port in %q", s)
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("address %q", h)
	}
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	a, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
}

// procs returns the instance's processes (PID to command line) from the
// engine's top, which lists every process of the container's PID
// namespace.
func (pi *provisionedImage) procs() (map[string]string, error) {
	out, err := exec.Command(pi.eng.Path, "top", pi.name).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s top: %v: %s", pi.eng.Path, err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("top printed %q", out)
	}
	head := strings.Fields(lines[0])
	pidCol := slices.Index(head, "PID")
	if pidCol < 0 {
		return nil, fmt.Errorf("no PID column in %q", lines[0])
	}
	got := map[string]string{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < len(head) {
			continue
		}
		got[f[pidCol]] = strings.Join(f[len(head)-1:], " ")
	}
	return got, nil
}

// bootstrapNames are the commands that would mean the instance installs,
// fetches or launches a package: package managers, interpreters, shells
// and downloaders.
var bootstrapNames = []string{"pip", "pip3", "uv", "uvx", "pipx", "npm", "npx", "node", "nodejs", "deno", "bun", "python", "python3",
	"sh", "bash", "dash", "ash", "curl", "wget", "git", "apt", "apt-get", "dnf", "microdnf", "yum", "rpm", "apk", "docker", "podman"}

func isBootstrap(cmd string) bool {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return false
	}
	base := path.Base(f[0])
	for _, n := range bootstrapNames {
		if base == n || strings.HasPrefix(base, n+".") || (n == "python" && strings.HasPrefix(base, "python3")) {
			return true
		}
	}
	return false
}

// TestNoRuntimeBootstrapImage (SR-3.6-2): the pinned image started with
// the generated configuration, which keeps stdio transport disabled
// (CheckEnvironment refuses any other value at Start, and the generated
// value is checked here), and one hosted package. While five calls of the
// package's tool run, the instance's processes are listed every 50 ms and
// its network namespace's TCP and UDP sockets read every 50 ms from a
// sidecar in that namespace: no process starts during the calls (so no
// package manager or interpreter), and no socket has a peer other than
// loopback, the hosted fixture's host and the engine's gateway (the
// published port's inbound connections), so no package registry is
// contacted.
func TestNoRuntimeBootstrapImage(t *testing.T) {
	reqtest.Verifies(t, "SR-3.6-2")
	env := Environment(Settings{Limits: Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}})
	if v := env["MCPGATEWAY_STDIO_TRANSPORT_ENABLED"]; !strings.EqualFold(v, "false") {
		t.Fatalf("generated MCPGATEWAY_STDIO_TRANSPORT_ENABLED=%q", v)
	}
	env["MCPGATEWAY_STDIO_TRANSPORT_ENABLED"] = "true"
	if err := CheckEnvironment(env, Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}); err == nil {
		t.Fatal("CheckEnvironment accepted stdio transport")
	}

	pi := startProvisionedImage(t, "smcp-cf-test-bootstrap")
	allowed := pi.allowedPeers(t)
	before, err := pi.procs()
	if err != nil {
		t.Fatal(err)
	}
	for pid, cmd := range before {
		if isBootstrap(cmd) && !strings.Contains(cmd, "gunicorn") {
			t.Logf("process before the calls: %s %s", pid, cmd)
		}
	}

	// The network watcher: one sidecar reads the namespace's sockets
	// every 50 ms until it is stopped.
	watch := pi.name + "-netwatch"
	cmd := exec.Command(pi.eng.Path, "run", "-d", "--rm", "--name", watch, "--network", "container:"+pi.name, "--entrypoint", "/bin/sh", pi.img,
		"-c", "while :; do cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null; sleep 0.05; done")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("network watcher: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(pi.eng.Path, "rm", "-f", watch).Run() })

	var mu sync.Mutex
	started := map[string]string{}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			now, err := pi.procs()
			if err != nil {
				continue
			}
			mu.Lock()
			for pid, c := range now {
				if _, ok := before[pid]; !ok {
					started[pid] = c
				}
			}
			mu.Unlock()
		}
	}()
	time.Sleep(time.Second)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if reached, _ := pi.admin.callReaches(ctx, "/servers/"+pi.pkg.ServerID+"/mcp", pi.pkg.Token, pi.pkg.Tools[0]); !reached {
			t.Fatalf("call %d did not reach the fixture", i+1)
		}
	}
	if n := pi.up.calls.Load(); n != 5 {
		t.Fatalf("the fixture recorded %d calls, want 5", n)
	}
	time.Sleep(time.Second)
	close(stop)
	<-done
	logs, err := exec.Command(pi.eng.Path, "logs", watch).Output()
	if err != nil {
		t.Fatalf("network watcher logs: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for pid, c := range started {
		t.Errorf("process started during the calls: %s %s (bootstrap command: %v)", pid, c, isBootstrap(c))
	}
	socks := parseProcNet(string(logs))
	if len(socks) == 0 {
		t.Fatal("the network watcher read no sockets")
	}
	peers := map[netip.Addr]bool{}
	for _, s := range socks {
		if s.state == tcpListen || !s.remote.Addr().IsValid() || s.remote.Addr().IsUnspecified() {
			continue
		}
		peers[s.remote.Addr()] = true
		if !allowed(s.remote.Addr()) {
			t.Errorf("socket %v -> %v (state %s): a peer other than loopback, the fixture host and the engine gateway", s.local, s.remote, s.state)
		}
	}
	t.Logf("peers seen during the calls: %v", peers)
}

// allowedPeers returns the check for a socket peer of the instance:
// loopback, the instance's own addresses, the hosted fixture's host
// (cftest.FixtureHost), the default gateway of its network namespace,
// through which the published loopback port's connections arrive (the
// bridge gateway with Docker, slirp4netns' host address with rootless
// Podman), and the name servers of its resolv.conf, which resolve the
// fixture's name. A package registry is none of these.
func (pi *provisionedImage) allowedPeers(t *testing.T) func(netip.Addr) bool {
	t.Helper()
	set := map[netip.Addr]bool{}
	for _, n := range pi.host.Nets {
		if p, err := netip.ParsePrefix(n); err == nil {
			set[p.Addr()] = true
		}
	}
	out, err := pi.sidecar("cat /proc/net/route; echo SOCKETS; cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6").CombinedOutput()
	if err != nil {
		t.Fatalf("route table: %v: %s", err, out)
	}
	routes, socks, _ := strings.Cut(string(out), "SOCKETS")
	for _, l := range strings.Split(routes, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		if a, err := procAddr(f[2] + ":0"); err == nil {
			set[a.Addr()] = true
		}
	}
	for _, s := range parseProcNet(socks) {
		if !s.local.Addr().IsUnspecified() {
			set[s.local.Addr()] = true
		}
	}
	conf, err := exec.Command(pi.eng.Path, "exec", pi.name, "cat", "/etc/resolv.conf").Output()
	if err != nil {
		t.Fatalf("resolv.conf: %v", err)
	}
	for _, l := range strings.Split(string(conf), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				set[a] = true
			}
		}
	}
	t.Logf("allowed peers besides loopback: %v", set)
	return func(a netip.Addr) bool { return a.IsLoopback() || set[a.Unmap()] }
}

// hs256 signs claims with key as a JSON Web Token.
func hs256(key []byte, claims map[string]any) string {
	enc := base64.RawURLEncoding
	head := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	msg := head + "." + enc.EncodeToString(body)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return msg + "." + enc.EncodeToString(m.Sum(nil))
}

// TestNoPathAroundGatewayImage (SR-4-3): the pinned image with one hosted
// package. The instance's listening sockets are read from its network
// namespace: the only one the host can reach is ContextForge's port, which
// the engine publishes on 127.0.0.1 only, and the container has no bind
// mount through which a Unix socket could be reached. From the harness
// host account (the test's own), every MCP and tool route of that port is
// tried without a token and with the credentials a harness holds (a
// Gateway session token, the same token as Basic credentials and as a
// query parameter, and a JSON Web Token naming the administrator but
// signed with another key): no tool is listed or invoked, and the
// fixture records no call. The package token, which only the Gateway's
// service identity holds (FR-22.36), then reaches the tool, so the probes
// would have seen a call.
func TestNoPathAroundGatewayImage(t *testing.T) {
	reqtest.Verifies(t, "SR-4-3")
	pi := startProvisionedImage(t, "smcp-cf-test-gatewaypath")

	out, err := pi.sidecar("cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; echo UNIX; cat /proc/net/unix").CombinedOutput()
	if err != nil {
		t.Fatalf("socket list: %v: %s", err, out)
	}
	inet, unix, _ := strings.Cut(string(out), "UNIX")
	listening := map[uint16]bool{}
	for _, s := range parseProcNet(inet) {
		if s.state == tcpListen || (s.state == "07" && !s.remote.Addr().IsValid()) {
			listening[s.local.Port()] = true
		}
	}
	if !listening[ContainerPort] {
		t.Fatalf("ContextForge's port %d is not listening: %v", ContainerPort, listening)
	}
	t.Logf("listening ports in the instance's namespace: %v", listening)
	ports, err := exec.Command(pi.eng.Path, "port", pi.name).Output()
	if err != nil {
		t.Fatal(err)
	}
	var published []string
	for _, l := range strings.Split(strings.TrimSpace(string(ports)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			published = append(published, l)
		}
	}
	want := fmt.Sprintf("%d/tcp -> 127.0.0.1:%d", ContainerPort, pi.in.Status().Port)
	if len(published) != 1 || published[0] != want {
		t.Fatalf("published ports %q, want only %q", published, want)
	}
	mounts, err := exec.Command(pi.eng.Path, "inspect", "--type", "container", "--format", "{{range .Mounts}}{{.Type}} {{end}}", pi.name).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range strings.Fields(string(mounts)) {
		if m != "volume" && m != "tmpfs" {
			t.Fatalf("the container has a %s mount", m)
		}
	}
	for _, l := range strings.Split(unix, "\n") {
		if f := strings.Fields(l); len(f) >= 8 && f[5] == "01" && strings.HasPrefix(f[7], "/") {
			t.Logf("unix listener inside the container (no bind mount reaches it): %s", f[7])
		}
	}

	harness := ids.Secret()
	key := make([]byte, 32)
	copy(key, ids.Secret())
	forged := hs256(key, map[string]any{"sub": AdminEmail, "email": AdminEmail, "is_admin": true, "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(), "aud": "mcpgateway-api", "iss": "mcpgateway"})
	type cred struct{ name, header, query string }
	creds := []cred{{name: "no token"}, {name: "harness token", header: "Bearer " + harness},
		{name: "harness token as Basic", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("harness:"+harness))},
		{name: "harness token as query parameter", query: "?token=" + harness + "&access_token=" + harness},
		{name: "forged administrator JWT", header: "Bearer " + forged}}
	tool := pi.pkg.Tools[0]
	call := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": map[string]any{}}}
	list := map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}}
	type route struct {
		method, path string
		body         any
	}
	srv := "/servers/" + pi.pkg.ServerID
	routes := []route{
		{http.MethodPost, srv + "/mcp", list}, {http.MethodPost, srv + "/mcp", call}, {http.MethodPost, srv + "/mcp/", call},
		{http.MethodPost, "/mcp", list}, {http.MethodPost, "/mcp", call}, {http.MethodPost, "/mcp/", call},
		{http.MethodPost, "/rpc", list}, {http.MethodPost, "/rpc", call}, {http.MethodPost, "/rpc/", call},
		{http.MethodGet, srv + "/sse", nil}, {http.MethodPost, srv + "/message", call},
		{http.MethodGet, "/tools", nil}, {http.MethodGet, "/v1/tools", nil}, {http.MethodGet, "/v1/servers", nil},
		{http.MethodGet, "/v1/servers/" + pi.pkg.ServerID + "/tools", nil}, {http.MethodGet, "/v1/gateways", nil},
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := pi.in.BaseURL()
	statuses := map[string][]int{}
	for _, c := range creds {
		for _, r := range routes {
			var body io.Reader
			if r.body != nil {
				raw, _ := json.Marshal(r.body)
				body = strings.NewReader(string(raw))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			req, err := http.NewRequestWithContext(ctx, r.method, base+r.path+c.query, body)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}
			resp, err := client.Do(req)
			var got []byte
			status := 0
			if err == nil {
				status = resp.StatusCode
				got, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
			}
			cancel()
			statuses[c.name] = append(statuses[c.name], status)
			if status/100 == 2 && strings.Contains(string(got), tool) {
				t.Errorf("%s: %s %s answered %d with the package's tool: %.300s", c.name, r.method, r.path, status, got)
			}
			if status/100 == 2 && strings.Contains(string(got), "A answered") {
				t.Errorf("%s: %s %s invoked the tool: %.300s", c.name, r.method, r.path, got)
			}
		}
	}
	t.Logf("HTTP status per credential, in route order: %v", statuses)
	if n := pi.up.calls.Load(); n != 0 {
		t.Fatalf("the fixture recorded %d calls from requests without the package token", n)
	}
	// The control: the package token reaches the tool on the same port.
	if reached, _ := pi.admin.callReaches(context.Background(), srv+"/mcp", pi.pkg.Token, tool); !reached || pi.up.calls.Load() != 1 {
		t.Fatalf("the package token did not reach the tool (calls %d)", pi.up.calls.Load())
	}
}
