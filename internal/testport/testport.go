// Package testport hands out loopback TCP ports for tests that must write
// a listener address into a configuration before the listener opens.
//
// A port taken from a "127.0.0.1:0" listener and released is in the
// operating system's ephemeral range, which outgoing connections also draw
// their source ports from. Under load (go test ./... runs packages in
// parallel, each making many connections), such a port is often in use as
// a source port by the time the configured listener binds it, and the bind
// fails with "address already in use". Free picks a random port below the
// ephemeral range instead, checks that it can be bound, and never returns
// the same port twice in one process.
package testport

import (
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Ports below the ephemeral range: Linux defaults to 32768-60999, macOS and
// Windows to 49152-65535. A narrower range read from the system is honored.
const (
	low  = 20000
	high = 32768
)

var (
	mu     sync.Mutex
	issued = map[int]bool{}
)

// Free returns a loopback port that was bindable when checked and that no
// earlier call in this process returned.
func Free(t testing.TB) int {
	t.Helper()
	top := high
	if l := ephemeralLow(); l > low+1000 && l < top {
		top = l
	}
	mu.Lock()
	defer mu.Unlock()
	for range 200 {
		p := low + rand.IntN(top-low) // #nosec G404 -- test port choice, not security relevant
		if issued[p] {
			continue
		}
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		_ = l.Close()
		issued[p] = true
		return p
	}
	// Fall back to the kernel's choice.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := l.Addr().(*net.TCPAddr).Port
	issued[p] = true
	return p
}

// ephemeralLow returns the low end of the Linux ephemeral port range, or 0.
func ephemeralLow() int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}
