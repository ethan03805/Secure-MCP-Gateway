//go:build windows

package pipeline

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

func probeMain(args []string) {
	out := map[string]string{}
	for _, a := range args {
		op, arg, _ := strings.Cut(a, ":")
		var err error
		switch op {
		case "read":
			_, err = os.ReadFile(arg)
		case "write":
			err = os.WriteFile(arg, []byte("x"), 0o600)
		case "dial":
			var c net.Conn
			if c, err = net.DialTimeout("tcp", arg, 3*time.Second); err == nil {
				c.Close()
			}
		case "temp":
			var f *os.File
			if f, err = os.CreateTemp("", "probe"); err == nil {
				f.Close()
			}
		}
		out[a] = "ok"
		if err != nil {
			out[a] = err.Error()
		}
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}

// TestWindowsMachineModePlacement runs the machine-mode path end to end
// on this runner (an administrator, as the elevated enable step is): the
// placement of a revision (AppContainer profile, access entries on the
// package tree, scratch directory and a read-only and a writable root,
// WFP filters and loopback exemption for the broker port), a backend
// started by SubprocessLauncher in that AppContainer, the hostile probes of
// FR-21.13 and FR-21.14 from inside it, and the removal at disable.
// Partial for FR-21.13, FR-21.14, SR-4.6-2 and SR-4.5-3: the Gateway does
// not run as the machine mode's virtual service account here, and the
// Egress Broker's proxy is replaced by a plain listener on the broker port.
func TestWindowsMachineModePlacement(t *testing.T) {
	reqtest.Partial(t, "FR-21.13", "FR-21.14", "SR-4.6-2", "SR-4.5-3")
	if _, err := winsandbox.OpenEngine(); err != nil {
		t.Skipf("the filter engine needs an administrator: %v", err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	id := "io.example.probe-" + hex.EncodeToString(b)
	base := t.TempDir()
	dirs := map[string]string{}
	for _, n := range []string{"tree", "scratch", "ro", "rw", "outside"} {
		dirs[n] = filepath.Join(base, n)
		if err := os.MkdirAll(dirs[n], 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(dirs["outside"], "secret.txt"), filepath.Join(dirs["ro"], "data.txt")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	backend := filepath.Join(dirs["tree"], "server.exe")
	if err := os.WriteFile(backend, body, 0o700); err != nil {
		t.Fatal(err)
	}
	ps := winsandbox.Placements{Dir: filepath.Join(base, "state", "appcontainer")}
	pl, err := ps.Ensure(winsandbox.PlacementRequest{ServerID: id, Revision: "1", Tree: dirs["tree"], Scratch: dirs["scratch"],
		Roots: []winsandbox.PathGrant{{Path: dirs["ro"]}, {Path: dirs["rw"], Write: true}}})
	if err != nil {
		t.Fatal(err)
	}
	removed := false
	t.Cleanup(func() {
		if !removed {
			_ = ps.Remove(id, "1")
		}
	})
	if again, err := ps.Ensure(winsandbox.PlacementRequest{ServerID: id, Revision: "1", Tree: dirs["tree"], Scratch: dirs["scratch"],
		Roots: []winsandbox.PathGrant{{Path: dirs["ro"]}, {Path: dirs["rw"], Write: true}}}); err != nil || again.BrokerPort != pl.BrokerPort {
		t.Fatalf("second enable: %+v %v", again, err)
	}
	broker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", pl.BrokerPort))
	if err != nil {
		t.Fatalf("broker port %d: %v", pl.BrokerPort, err)
	}
	defer broker.Close()
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, ln := range []net.Listener{broker, other} {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	home, _ := os.UserHomeDir()
	probes := map[string]bool{
		"read:" + filepath.Join(dirs["ro"], "data.txt"):    true,
		"write:" + filepath.Join(dirs["rw"], "x.txt"):      true,
		"write:" + filepath.Join(dirs["scratch"], "x.txt"): true,
		"temp:":                          true,
		"dial:" + broker.Addr().String(): true,
		"read:" + filepath.Join(dirs["outside"], "secret.txt"): false,
		"read:" + filepath.Join(home, "NTUSER.DAT"):            false,
		"write:" + filepath.Join(dirs["ro"], "x.txt"):          false,
		"write:" + filepath.Join(dirs["tree"], "x.txt"):        false,
		"read:" + filepath.Join(ps.Dir, pl.Profile+".json"):    false,
		"dial:" + other.Addr().String():                        false,
		"dial:1.1.1.1:443":                                     false,
	}
	var args []string
	for p := range probes {
		args = append(args, p)
	}
	l := SubprocessLauncher{TerminateAfter: time.Second}
	p, err := l.Launch(context.Background(), ServerSpec{Alias: "probe", Command: backend, Args: args, Dir: dirs["scratch"],
		Env: map[string]string{helperEnv: "probe"}, Container: pl.Profile, EgressProxyPort: pl.BrokerPort})
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(p).ReadString('\n')
	p.Close()
	var got map[string]string
	if jerr := json.Unmarshal([]byte(line), &got); jerr != nil {
		t.Fatalf("backend output %q (%v); stderr %q", line, err, p.Stderr())
	}
	for pr, want := range probes {
		if (got[pr] == "ok") != want {
			t.Errorf("%s: %s (expected success %v)", pr, got[pr], want)
		}
	}

	c, err := pl.Container()
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Remove(id, "1"); err != nil {
		t.Fatal(err)
	}
	removed = true
	for _, d := range []string{dirs["tree"], dirs["scratch"], dirs["ro"], dirs["rw"]} {
		if es, err := winsandbox.Entries(d, c.SID); err != nil || len(es) != 0 {
			t.Errorf("%s: entries remain after disable: %+v %v", d, es, err)
		}
	}
	if ok, _ := winsandbox.LoopbackExempt(c.SID); ok {
		t.Error("loopback exemption remains after disable")
	}
	if _, ok := ps.Lookup(id, "1"); ok {
		t.Error("placement record remains after disable")
	}
	var _ = windows.ERROR_ACCESS_DENIED
}
