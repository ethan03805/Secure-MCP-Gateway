//go:build windows

package winsandbox

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln
}

// containedBackend prepares a package directory holding a copy of the test
// binary and a scratch directory, both granted to the container.
func containedBackend(t *testing.T, c *Container) (backend, scratch string) {
	t.Helper()
	d := mkdirs(t, t.TempDir(), "pkg", "scratch")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	backend = filepath.Join(d["pkg"], "backend.exe")
	copyFile(t, exe, backend)
	if err := Grant(d["pkg"], c.SID, ReadExecute); err != nil {
		t.Fatal(err)
	}
	if err := Grant(d["scratch"], c.SID, Modify); err != nil {
		t.Fatal(err)
	}
	return backend, d["scratch"]
}

// TestWindowsWFPEgress runs the hostile egress attempts of FR-21.14 from a
// backend in an AppContainer whose filters were installed as the enable step
// installs them: only TCP to the broker's loopback port succeeds; another
// loopback port (reachable through the loopback exemption if the filter did
// not hold), an external address and DNS over UDP fail. Removing the filters
// removes the exemption too, and uninstalling leaves no filter of the
// Gateway's provider (SR-4.5-3). Partial for FR-21.14: the broker's own
// destination checks are those of FR-5 and tested in internal/egress; the
// machine-mode enable step that calls this is not built yet.
func TestWindowsWFPEgress(t *testing.T) {
	reqtest.Partial(t, "FR-21.14", "SR-4.5-3")
	e, err := OpenEngine()
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || strings.Contains(err.Error(), "0x00000005") {
			t.Skip("the filter engine needs an administrator")
		}
		t.Fatal(err)
	}
	defer e.Close()
	c := testProfile(t)
	t.Cleanup(func() { _ = e.Uninstall([]*windows.SID{c.SID}) })
	broker, other := listenLoopback(t), listenLoopback(t)
	brokerPort := uint16(broker.Addr().(*net.TCPAddr).Port)
	if err := e.AddBackendFilters(c.SID, brokerPort); err != nil {
		t.Fatal(err)
	}
	// Installing twice replaces, not duplicates.
	if err := e.AddBackendFilters(c.SID, brokerPort); err != nil {
		t.Fatal(err)
	}
	fs, err := e.Filters()
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != len(filterRoles) {
		t.Fatalf("filters of the provider: %+v", fs)
	}
	if ok, err := LoopbackExempt(c.SID); err != nil || !ok {
		t.Fatalf("loopback exemption = %v, %v", ok, err)
	}
	backend, scratch := containedBackend(t, c)
	probes := map[string]bool{
		"dial:" + broker.Addr().String(): true,
		"dial:" + other.Addr().String():  false,
		"dial:1.1.1.1:443":               false,
		"dns:8.8.8.8:53":                 false,
	}
	run := func() map[string]string {
		var args []string
		for p := range probes {
			args = append(args, p)
		}
		job := newJob(t, Limits{MemoryBytes: 256 << 20, Processes: 4})
		return runContained(t, backend, c, job, scratch, "escape", args)
	}
	results := run()
	for p, want := range probes {
		got := results[p]
		if (got == "ok") != want {
			t.Errorf("%s: %s (expected success %v)", p, got, want)
		}
	}

	if err := e.RemoveBackendFilters(c.SID); err != nil {
		t.Fatal(err)
	}
	if fs, _ := e.Filters(); len(fs) != 0 {
		t.Fatalf("filters remain after disable: %+v", fs)
	}
	if ok, _ := LoopbackExempt(c.SID); ok {
		t.Fatal("loopback exemption remains after disable")
	}
	if got := run()["dial:"+broker.Addr().String()]; got == "ok" {
		t.Fatal("broker port reachable without the exemption")
	}
	if err := e.Uninstall([]*windows.SID{c.SID}); err != nil {
		t.Fatal(err)
	}
	if fs, _ := e.Filters(); len(fs) != 0 {
		t.Fatalf("filters remain after uninstall: %+v", fs)
	}
}
