package bundle

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The Enforced port range is the set contextforge_ports of the host's
// nftables table, whose output rule admits only smcp-core (FR-22.26), and
// the listener port is chosen from it, skipping ports in use.
func TestEnforcedPorts(t *testing.T) {
	reqtest.Partial(t, "FR-22.26")
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packaging", "linux", "nftables", "smcp.nft"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)set contextforge_ports \{.*?elements = \{ (\d+)-(\d+) \}`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("smcp.nft has no set contextforge_ports with one range")
	}
	first, _ := strconv.Atoi(string(m[1]))
	last, _ := strconv.Atoi(string(m[2]))
	if first != EnforcedPorts.First || last != EnforcedPorts.Last {
		t.Fatalf("smcp.nft admits %d-%d, the Connector uses %+v", first, last, EnforcedPorts)
	}
	if !regexp.MustCompile(`tcp dport @contextforge_ports meta skuid != "smcp-core" counter reject`).Match(raw) {
		t.Fatal("smcp.nft does not reject other users' connections to contextforge_ports")
	}
	// A small range with one port taken: the other is chosen.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	p := busy.Addr().(*net.TCPAddr).Port
	r := PortRange{First: p, Last: p + 1}
	for range 5 {
		got, err := pickPort(r)
		if err != nil {
			t.Skipf("port %d is in use too: %v", p+1, err)
		}
		if got != p+1 {
			t.Fatalf("picked %d from %+v with %d in use", got, r, p)
		}
	}
	if _, err := pickPort(PortRange{First: p, Last: p}); err == nil {
		t.Fatal("a range whose only port is in use gave a port")
	}
}
