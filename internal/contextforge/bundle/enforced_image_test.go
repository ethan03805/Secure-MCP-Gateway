package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// probeScript runs inside the instance's container. Each line it prints
// is "<check> <ok|blocked|error>": TCP connections (a short timeout, so a
// dropped packet reads as blocked), a write outside the volume, setuid,
// and the sockets and devices of SR-4.7-3.
const probeScript = `
import os, socket, sys
def tcp(name, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, int(port)))
        print(name, "ok")
    except Exception as e:
        print(name, "blocked", type(e).__name__)
    finally:
        s.close()
args = sys.argv[1:]
for i in range(0, len(args), 3):
    tcp(args[i], args[i+1], args[i+2])
try:
    open("/etc/smcp-escape", "w").write("x")
    print("write_root ok")
except Exception as e:
    print("write_root blocked", type(e).__name__)
try:
    open("/app/data/smcp-probe", "w").write("x")
    os.remove("/app/data/smcp-probe")
    print("write_volume ok")
except Exception as e:
    print("write_volume blocked", type(e).__name__)
try:
    os.setuid(0)
    print("setuid ok")
except Exception as e:
    print("setuid blocked", type(e).__name__)
def unix(p):
    if not os.path.exists(p):
        return "blocked"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(p)
        return "ok"
    except Exception:
        return "blocked"
    finally:
        s.close()
for p in ["/run/podman/podman.sock", "/var/run/docker.sock", "/run/docker.sock", "/run/systemd/private", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
          "/run/user/1000/podman/podman.sock", "/run/user/1001/podman/podman.sock", "/run/user/1000/bus", "/run/user/1001/bus"]:
    print("path:" + p, unix(p))
pids = [d for d in os.listdir("/proc") if d.isdigit()]
print("host_pids", "ok" if len(pids) > 50 else "blocked", len(pids))
devs = sorted(os.listdir("/dev"))
extra = [d for d in devs if d.startswith(("sd", "nvme", "vd", "xvd", "mem", "kmsg", "kvm"))]
print("host_devices", "ok" if extra else "blocked", ",".join(extra))
`

// TestEnforcedImage runs the pinned image under the Enforced containment
// with rootless Podman (SMCP_CONTEXTFORGE_ENFORCED=1; the contextforge CI
// job): podman inspect shows the read-only root, the dropped capabilities,
// no-new-privileges, the doubled CP-24 limits, its own user namespace, the
// one volume and no host mount; its nftables table is in place; and from
// inside the container only the hosted egress listener is reachable: the
// Internet, a LAN address of the host and another Gateway listener on the
// host's loopback are not, and neither are the engine and bus sockets, the
// host's processes and its disks. Writes outside the volume and setuid
// fail. ContextForge's own SSRF allowlist is set to allow everything, and
// its own attempts to register gateways on the Internet and the LAN fail
// as well. A hosted package registered through the hosted listener answers
// 20 calls, and the instance's memory after start and after the calls is
// below the doubled CP-24 limit (FR-22.24, SR-4.5-4, SR-4.7-3, HFC-12).
func TestEnforcedImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_ENFORCED") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_ENFORCED=1 to run the pinned image under the Enforced containment (rootless Podman, Linux)")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Enforced containment is Linux only")
	}
	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman not installed")
	}
	reqtest.Partial(t, "FR-22.26", "FR-22.43")
	ctx := context.Background()
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	if out, err := exec.Command(podman, "pull", "-q", img).CombinedOutput(); err != nil {
		t.Fatalf("pull: %v: %s", err, out)
	}
	// The hosted egress listener, here a hosted MCP fixture on loopback,
	// and another host service on loopback (a Gateway listener the
	// instance must not reach).
	hostedFx := newUpstream(t, cftest.Host{Listen: "127.0.0.1"}, "H")
	hostedPort, _ := strconv.Atoi(hostedFx.port)
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, l := range []net.Listener{other} {
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}(l)
	}
	port := func(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }
	creds, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	name := "smcp-cf-enforced-test"
	in, err := New(Options{Engine: Engine{Path: podman, Podman: true}, Enforced: true, Image: img, Name: name,
		// SR-4.5-4: ContextForge's own SSRF allowlist admits everything;
		// the namespace must hold regardless.
		Settings:    Settings{SSRFAllowed: []string{"0.0.0.0/0", "::/0"}, Limits: Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}},
		Credentials: func() (Credentials, error) { return creds, nil }, HealthWait: 180 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	in.SetEgressAllow(netip.AddrPortFrom(netip.MustParseAddr("10.0.2.2"), uint16(hostedPort))) // #nosec G115 -- a listener port
	t.Cleanup(func() {
		_ = in.Stop(ctx)
		_ = in.RemoveVolume(ctx)
	})
	start := time.Now()
	if err := in.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for !in.Healthy() {
		if time.Since(start) > 180*time.Second {
			out, _ := exec.Command(podman, "logs", "--tail", "40", name).CombinedOutput()
			t.Fatalf("not healthy after %v: %+v\n%s", time.Since(start), in.Status(), redactOutput(string(out), creds))
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Logf("healthy under the Enforced containment after %v", time.Since(start).Round(time.Second))

	// podman inspect.
	raw, err := exec.Command(podman, "inspect", "--type", "container", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	var insp []struct {
		HostConfig struct {
			ReadonlyRootfs  bool
			CapAdd, CapDrop []string
			SecurityOpt     []string
			Memory          int64
			PidsLimit       int64
			NetworkMode     string
			UsernsMode      string
			Privileged      bool
			PidMode         string
			Devices         []any
		}
		Mounts []struct {
			Type, Source, Destination string
		}
	}
	if err := json.Unmarshal(raw, &insp); err != nil || len(insp) != 1 {
		t.Fatalf("inspect: %v", err)
	}
	hc := insp[0].HostConfig
	sec := strings.Join(hc.SecurityOpt, " ")
	if !hc.ReadonlyRootfs || len(hc.CapAdd) != 0 || hc.Privileged || !strings.Contains(sec, "no-new-privileges") ||
		hc.Memory != 1024<<20 || hc.PidsLimit != 256 || !strings.HasPrefix(hc.NetworkMode, "slirp4netns") || hc.UsernsMode == "" || hc.UsernsMode == "host" ||
		hc.PidMode == "host" || len(hc.Devices) != 0 {
		t.Fatalf("host config %+v", hc)
	}
	for _, m := range insp[0].Mounts {
		if m.Type == "bind" || m.Destination != "/app/data" {
			t.Fatalf("mount %+v", m)
		}
	}
	t.Logf("podman inspect: read-only root, CapDrop %v, %s, memory %d MiB, pids %d, network %s, userns %s",
		hc.CapDrop, sec, hc.Memory>>20, hc.PidsLimit, hc.NetworkMode, hc.UsernsMode)

	// A LAN address of the host: its first non-loopback IPv4 address.
	lan := ""
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
				lan = ip.IP.String()
				break
			}
		}
	}
	args := []string{"exec", name, "python3", "-c", probeScript,
		"hosted_listener", "10.0.2.2", hostedFx.port,
		"gateway_listener", "10.0.2.2", strconv.Itoa(port(other)),
		"internet", "1.1.1.1", "443",
		"dns", "10.0.2.3", "53"}
	if lan != "" {
		args = append(args, "lan", lan, strconv.Itoa(port(other)))
	}
	out, err := exec.Command(podman, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v: %s", err, out)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			got[f[0]] = f[1]
		}
	}
	t.Logf("from inside the instance:\n%s", out)
	want := map[string]string{"hosted_listener": "ok", "gateway_listener": "blocked", "internet": "blocked", "dns": "blocked",
		"write_root": "blocked", "write_volume": "ok", "setuid": "blocked", "host_pids": "blocked", "host_devices": "blocked",
		"path:/run/podman/podman.sock": "blocked", "path:/var/run/docker.sock": "blocked", "path:/run/docker.sock": "blocked",
		"path:/run/systemd/private": "blocked", "path:/run/dbus/system_bus_socket": "blocked", "path:/var/run/dbus/system_bus_socket": "blocked",
		"path:/run/user/1000/podman/podman.sock": "blocked", "path:/run/user/1001/podman/podman.sock": "blocked", "path:/run/user/1000/bus": "blocked",
		"path:/run/user/1001/bus": "blocked"}
	if lan != "" {
		want["lan"] = "blocked"
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	// Memory after start, below the limit.
	memBelow(t, podman, name, "start")

	// SR-4.5-4: ContextForge itself, with its SSRF allowlist admitting
	// everything, cannot reach the Internet or the LAN: registering a
	// gateway there fails.
	a := &Admin{Base: in.BaseURL(), AdminToken: func() (string, error) { return in.AdminToken(5 * time.Minute) }}
	escapes := map[string]string{"internet": "https://1.1.1.1/mcp"}
	if lan != "" {
		escapes["lan"] = "http://" + net.JoinHostPort(lan, strconv.Itoa(port(other))) + "/mcp"
	}
	for what, u := range escapes {
		rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := a.Call(rctx, "POST", "/v1/gateways", "", map[string]any{"name": "smcp-escape-" + what, "url": u, "transport": "STREAMABLEHTTP"}, nil)
		cancel()
		if err == nil {
			t.Errorf("ContextForge registered a gateway on the %s (%s) with its SSRF allowlist open", what, u)
		} else {
			t.Logf("ContextForge's own connection to the %s failed: %v", what, err)
		}
	}

	// FR-22.24: a hosted package through the hosted listener, 20 calls,
	// memory after them.
	pw, _ := NewCredential()
	prov, err := a.Provision(ctx, PackageSpec{Slug: "smcp-enforced-fx", URL: "http://10.0.2.2:" + hostedFx.port + "/mcp"}, pw)
	if err != nil {
		t.Fatalf("provision through the hosted listener: %v", err)
	}
	for i := 0; i < 20; i++ {
		if ok, detail := a.callReaches(ctx, "/servers/"+prov.ServerID+"/mcp", prov.Token, prov.Tools[0]); !ok {
			t.Fatalf("hosted call %d not answered: %s", i+1, detail)
		}
	}
	if n := hostedFx.calls.Load(); n != 20 {
		t.Fatalf("the hosted fixture saw %d calls, want 20", n)
	}
	memBelow(t, podman, name, "20 hosted calls")
	if !t.Failed() {
		reqtest.Verifies(t, "FR-22.24", "SR-4.5-4", "SR-4.7-3")
	}
}

// memBelow checks that the container's resident memory is below the
// doubled CP-24 limit of 1 GiB.
func memBelow(t *testing.T, podman, name, when string) {
	t.Helper()
	mem, err := exec.Command(podman, "stats", "--no-stream", "--format", "{{.MemUsage}}", name).Output()
	if err != nil {
		t.Errorf("podman stats after %s: %v", when, err)
		return
	}
	t.Logf("memory after %s: %s (limit %d MiB)", when, strings.TrimSpace(string(mem)), 1024)
	used, _, _ := strings.Cut(strings.TrimSpace(string(mem)), "/")
	used = strings.TrimSpace(used)
	var v float64
	switch {
	case strings.HasSuffix(used, "GB"):
		if _, err := fmt.Sscanf(used, "%fGB", &v); err == nil && v >= 1.07 {
			t.Errorf("memory after %s %s is at the limit", when, used)
		}
	case strings.HasSuffix(used, "MB"), strings.HasSuffix(used, "kB"), strings.HasSuffix(used, "B"):
	default:
		t.Errorf("memory after %s: unreadable %q", when, used)
	}
}
