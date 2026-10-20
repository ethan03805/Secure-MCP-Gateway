// Package cftest helps the pinned-image tests of the ContextForge Connector
// reach fixture MCP servers on the host from the bundled instance's
// container.
package cftest

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// Host says where a fixture server listens and how the container names it.
type Host struct {
	// Listen is the host address a fixture listens on (port 0 is added).
	Listen string
	// Name is the host name or address the container uses in fixture URLs.
	Name string
	// Nets are the SSRF allowlist entries that admit Name.
	Nets []string
}

// FixtureHost returns where fixtures listen for the container engine at
// engine running image img. On Linux the container reaches the host at the
// default bridge's gateway address, so fixtures listen there (not on
// loopback, which the container cannot reach). Docker Desktop instead
// forwards host.docker.internal to the host's loopback, so fixtures listen
// on 127.0.0.1 and the allowlist holds the addresses host.docker.internal
// has inside the image. The test is skipped when neither works.
func FixtureHost(t *testing.T, engine, img string) Host {
	t.Helper()
	if runtime.GOOS == "linux" {
		out, err := exec.Command(engine, "network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}").CombinedOutput()
		if err != nil {
			t.Skipf("no default bridge network: %s", out)
		}
		for _, f := range strings.Fields(string(out)) {
			if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
				return Host{Listen: f, Name: f, Nets: []string{f + "/32"}}
			}
		}
		t.Skipf("the default bridge network has no IPv4 gateway: %s", out)
	}
	py := "import socket,ipaddress\nfor a in sorted({x[4][0] for x in socket.getaddrinfo('host.docker.internal',None)}):\n print(a+('/32' if ipaddress.ip_address(a).version==4 else '/128'))"
	out, err := exec.Command(engine, "run", "--rm", "--network", "bridge", "--entrypoint", "python3", img, "-c", py).CombinedOutput()
	if err != nil {
		t.Skipf("host.docker.internal is not resolvable in this engine: %s", out)
	}
	nets := CIDRs(string(out))
	if len(nets) == 0 {
		t.Skipf("host.docker.internal has no address in this engine: %s", out)
	}
	return Host{Listen: "127.0.0.1", Name: "host.docker.internal", Nets: nets}
}

// URL is the fixture URL the container uses for a fixture on port.
func (h Host) URL(port string) string {
	return "http://" + net.JoinHostPort(h.Name, port) + "/mcp"
}

// CIDRs keeps the network lines of an engine's output (a pull prints
// progress lines first).
func CIDRs(out string) []string {
	var nets []string
	for _, f := range strings.Fields(out) {
		if _, _, err := net.ParseCIDR(f); err == nil {
			nets = append(nets, f)
		}
	}
	return nets
}
