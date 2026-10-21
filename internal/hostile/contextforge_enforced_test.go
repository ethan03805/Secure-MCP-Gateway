//go:build hostile

package hostile

import (
	"context"
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
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
)

func init() { cfChecks["HFC-12"] = hfc12 }

// HFC-12 (Enforced profile): the pinned ContextForge image runs under the
// Enforced containment (rootless Podman, its own user namespace, the
// nftables table in its network namespace) and, from inside it, tries the
// Internet, a LAN address of the host, the Gateway's harness and control
// listeners and the engine and bus sockets: every connection fails, and
// only its own listener and the hosted egress listener are reachable
// (SR-4.5-4, SR-4.7-3). It runs where SMCP_HOSTILE_PROFILE=enforced and
// SMCP_CONTEXTFORGE_IMAGE=1 (the contextforge job).
func hfc12(t *testing.T) (string, bool) {
	if suiteProfile() != "enforced" {
		return "not asserted (Enforced row, " + suiteProfile() + " profile)", false
	}
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" || runtime.GOOS != "linux" {
		return "not asserted: needs the pinned image (SMCP_CONTEXTFORGE_IMAGE=1) on Linux", false
	}
	podman, err := exec.LookPath("podman")
	if err != nil {
		return "not asserted: podman not installed", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	if out, err := exec.CommandContext(ctx, podman, "pull", "-q", img).CombinedOutput(); err != nil {
		return fmt.Sprintf("pull: %v %s", err, out), false
	}
	listen := func() (net.Listener, string) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		return l, strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	}
	hosted, hp := listen()
	defer hosted.Close()
	harness, harnessPort := listen()
	defer harness.Close()
	control, controlPort := listen()
	defer control.Close()
	creds, err := bundle.NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	in, err := bundle.New(bundle.Options{Engine: bundle.Engine{Path: podman, Podman: true}, Enforced: true, Image: img, Name: "smcp-cf-hfc12",
		Settings:    bundle.Settings{SSRFAllowed: []string{"10.0.2.2/32"}, Limits: bundle.Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}},
		Credentials: func() (bundle.Credentials, error) { return creds, nil }, HealthWait: 180 * time.Second, Ports: bundle.EnforcedPorts})
	if err != nil {
		t.Fatal(err)
	}
	hostedPort, _ := strconv.Atoi(hp)
	in.SetEgressAllow(netip.AddrPortFrom(netip.MustParseAddr("10.0.2.2"), uint16(hostedPort))) // #nosec G115 -- a listener port
	defer func() {
		_ = in.Stop(context.Background())
		_ = in.RemoveVolume(context.Background())
	}()
	if err := in.Start(ctx); err != nil {
		return "start under the Enforced containment: " + err.Error(), false
	}
	for !in.Healthy() {
		if ctx.Err() != nil {
			return "the instance did not become healthy", false
		}
		time.Sleep(250 * time.Millisecond)
	}
	lan := ""
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
				lan = ip.IP.String()
				break
			}
		}
	}
	targets := [][3]string{{"hosted_listener", "10.0.2.2", hp}, {"harness_listener", "10.0.2.2", harnessPort}, {"control_listener", "10.0.2.2", controlPort},
		{"internet", "1.1.1.1", "443"}, {"dns", "10.0.2.3", "53"}}
	if lan != "" {
		targets = append(targets, [3]string{"lan", lan, harnessPort})
	}
	got, out, err := bundle.ProbeInside(ctx, podman, in.Name(), targets...)
	if err != nil {
		return fmt.Sprintf("%v: %s", err, out), false
	}
	var refused, reached []string
	pass := got["hosted_listener"] == "ok"
	for k, v := range got {
		switch {
		case k == "hosted_listener" || k == "write_volume":
		case strings.HasPrefix(k, "path:") || k == "internet" || k == "dns" || k == "lan" || k == "harness_listener" || k == "control_listener" ||
			k == "host_pids" || k == "host_devices" || k == "write_root" || k == "setuid":
			if v == "blocked" {
				refused = append(refused, k)
			} else {
				reached = append(reached, k)
				pass = false
			}
		}
	}
	return fmt.Sprintf("from inside the instance: hosted listener %s; refused %d (%s); reached %v", got["hosted_listener"], len(refused), strings.Join(refused, ", "), reached),
		pass && len(refused) >= 10
}
