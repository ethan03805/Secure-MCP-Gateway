//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// graphPort is the Bolt port in the set graph_ports of
// packaging/linux/nftables/smcp.nft (the default of [graph] uri).
const graphPort = "7687"

// connectAs opens a TCP connection to addr as user (sudo -u) with bash's
// /dev/tcp and reports whether it was established.
func connectAs(t *testing.T, user, addr string) (bool, string) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	out, err := sudoOut(t, "", "-u", user, "timeout", "5", "bash", "-c", "exec 3<>/dev/tcp/"+host+"/"+port)
	return err == nil, strings.TrimSpace(out)
}

// listen accepts connections on addr, counts them and returns the address
// it listens on.
func listen(t *testing.T, addr string) (*atomic.Int64, string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	return &n, ln.Addr().String()
}

// TestGraphPortFirewallOnHost runs on an Enforced installation made by
// `smcpctl install --profile enforced` (scripts/ci-systemd.sh), whose
// nftables table inet smcp is loaded. A listener stands in for the graph
// engine on 127.0.0.1:7687 and [::1]:7687.
//
// SR-4.2-1: connections to the database port are admitted only from
// smcp-core, the identity smcpd and its Data Access Service (E-26) run as
// in release 1.x (SR-4.1-1); every other CP-46 identity (smcp-srv, the
// server identity, among them), nobody, root and the operator's account
// are refused before they reach the listener. The connection from a
// sandbox (a server container of smcp-srv with network "none") is made
// by scripts/ci-systemd.sh through the sandbox probe and refused too. The
// engine's own loopback-only listener is checked by smcpd from the
// engine's effective settings (internal/graph.TestEngineCheckAndMemorySampling)
// and the input chain drops the port on every interface but loopback.
//
// SR-7.4-1 (firewall part; Inspection, so Partial here): processes of
// smcp-data, the identity the graph engine runs as in the Enforced
// profile, cannot open connections, on loopback or to the network, while
// smcp-core can reach the same loopback listener.
//
// It needs sudo and the installed nftables table, so it runs only with
// SMCP_ENFORCED_FIREWALL_TEST=1 (scripts/ci-systemd.sh).
func TestGraphPortFirewallOnHost(t *testing.T) {
	if os.Getenv("SMCP_ENFORCED_FIREWALL_TEST") != "1" {
		t.Skip("needs the Enforced installation's nftables table; set SMCP_ENFORCED_FIREWALL_TEST=1 after scripts/ci-systemd.sh installed it")
	}
	reqtest.Verifies(t, "SR-4.2-1")
	reqtest.Partial(t, "SR-7.4-1")
	if out, err := sudoOut(t, "", "nft", "list", "table", "inet", "smcp"); err != nil {
		t.Fatalf("the nftables table inet smcp is not loaded: %v %s", err, out)
	} else {
		t.Logf("nft list table inet smcp:\n%s", out)
	}

	for _, addr := range []string{net.JoinHostPort("127.0.0.1", graphPort), net.JoinHostPort("::1", graphPort)} {
		accepted, _ := listen(t, addr)
		ok, out := connectAs(t, "smcp-core", addr)
		if !ok {
			t.Fatalf("smcp-core cannot connect to %s: %s", addr, out)
		}
		waitCount(accepted, 1)
		if got := accepted.Load(); got != 1 {
			t.Fatalf("%s: %d connections accepted after smcp-core's, want 1", addr, got)
		}
		for _, id := range append(append([]string{}, otherIdentities...), "root") {
			if ok, out := connectAs(t, id, addr); ok {
				t.Errorf("%s connected to the graph port %s", id, addr)
			} else {
				t.Logf("%s -> %s refused: %s", id, addr, out)
			}
		}
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			c.Close()
			t.Errorf("the operator's account connected to the graph port %s", addr)
		} else if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("the operator's account to %s: %v, want connection refused", addr, err)
		}
		time.Sleep(200 * time.Millisecond)
		if got := accepted.Load(); got != 1 {
			t.Errorf("%s: %d connections reached the listener, want only smcp-core's", addr, got)
		}
	}

	// SR-7.4-1: smcp-data opens no connections.
	other, otherAddr := listen(t, "127.0.0.1:0")
	if ok, out := connectAs(t, "smcp-core", otherAddr); !ok {
		t.Fatalf("smcp-core cannot connect to %s: %s", otherAddr, out)
	}
	waitCount(other, 1)
	for _, dst := range []string{otherAddr, "1.1.1.1:443", "[2606:4700:4700::1111]:443"} {
		if ok, out := connectAs(t, "smcp-data", dst); ok {
			t.Errorf("smcp-data (the graph engine's identity) connected to %s", dst)
		} else {
			t.Logf("smcp-data -> %s refused: %s", dst, out)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if got := other.Load(); got != 1 {
		t.Errorf("%d connections reached the loopback listener, want only smcp-core's", got)
	}
}

func waitCount(n *atomic.Int64, want int64) {
	for i := 0; i < 50 && n.Load() < want; i++ {
		time.Sleep(20 * time.Millisecond)
	}
}
