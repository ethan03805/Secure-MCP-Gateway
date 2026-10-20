//go:build windows

package winsandbox

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// probe runs one escape attempt from inside the backend and returns "ok" or
// the error text.
func probe(op, arg string) string {
	var err error
	switch op {
	case "read":
		_, err = os.ReadFile(arg)
	case "list":
		_, err = os.ReadDir(arg)
	case "write":
		err = os.WriteFile(arg, []byte("x"), 0o600)
	case "dial":
		var c net.Conn
		c, err = net.DialTimeout("tcp", arg, 3*time.Second)
		if c != nil {
			c.Close()
		}
	case "dns": // one DNS query over UDP, waiting for any answer
		var c net.Conn
		if c, err = net.Dial("udp", arg); err == nil {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
			if _, err = c.Write(q); err == nil {
				_, err = c.Read(make([]byte, 512))
			}
		}
	case "spawnread": // a child of the backend tries the read
		cmd := exec.Command(os.Args[0], "read:"+arg)
		cmd.Env = append(os.Environ(), helperEnv+"=escape")
		var b []byte
		b, err = cmd.Output()
		if err == nil {
			var m map[string]string
			if err = json.Unmarshal(b, &m); err == nil {
				return "child " + m["read:"+arg]
			}
		}
	default:
		return "unknown probe " + op
	}
	if err != nil {
		return err.Error()
	}
	return "ok"
}

// testProfile creates a throwaway AppContainer profile.
func testProfile(t *testing.T) *Container {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "smcp-test-" + hex.EncodeToString(b)
	c, err := CreateProfile(name, "Secure MCP Gateway test "+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := DeleteProfile(name); err != nil {
			t.Errorf("delete profile: %v", err)
		}
	})
	return c
}

func mkdirs(t *testing.T, base string, names ...string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, n := range names {
		p := filepath.Join(base, n)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		m[n] = p
	}
	return m
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestWindowsAppContainerEscapes runs the hostile escape attempts of FR-21.13
// from a backend in an AppContainer with no capabilities and the SR-4.6-2
// grants (package tree read and execute, scratch directory, one read-only and
// one writable slot): reading the user's profile and another directory of
// the user, reading the Gateway's state, writing outside the scratch
// directory and the writable slot, a TCP connection to loopback and to an
// external address, and a child process repeating the read. Partial for
// FR-21.13 and SR-4.6-2: enablement in the machine mode and the health cause
// are tested separately.
func TestWindowsAppContainerEscapes(t *testing.T) {
	reqtest.Partial(t, "FR-21.13", "SR-4.6-2")
	c := testProfile(t)
	base := t.TempDir()
	d := mkdirs(t, base, "pkg", "scratch", "ro", "rw", "outside", "state")
	for name, body := range map[string]string{"outside/secret.txt": "s", "state/evidence.key": "k", "ro/data.txt": "d"} {
		if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(name)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	backend := filepath.Join(d["pkg"], "backend.exe")
	copyFile(t, exe, backend)
	for path, a := range map[string]Access{d["pkg"]: ReadExecute, d["scratch"]: Modify, d["ro"]: ReadExecute, d["rw"]: Modify} {
		if err := Grant(path, c.SID, a); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	home, _ := os.UserHomeDir()
	probes := map[string]bool{ // probe -> expected to succeed
		"read:" + filepath.Join(d["ro"], "data.txt"):        true,
		"write:" + filepath.Join(d["scratch"], "x.txt"):     true,
		"write:" + filepath.Join(d["rw"], "x.txt"):          true,
		"read:" + filepath.Join(d["outside"], "secret.txt"): false,
		"list:" + home: false,
		"read:" + filepath.Join(d["state"], "evidence.key"): false,
		"list:" + d["state"]:                                                         false,
		"write:" + filepath.Join(d["outside"], "x.txt"):                              false,
		"write:" + filepath.Join(d["ro"], "x.txt"):                                   false,
		"write:" + filepath.Join(d["pkg"], "x.txt"):                                  false,
		"write:" + filepath.Join(os.Getenv("SYSTEMROOT"), "Temp", "smcp-escape.txt"): false,
		"dial:" + ln.Addr().String():                                                 false,
		"dial:1.1.1.1:443":                                                           false,
		"spawnread:" + filepath.Join(d["outside"], "secret.txt"):                     false,
	}
	var args []string
	for p := range probes {
		args = append(args, p)
	}
	job := newJob(t, Limits{MemoryBytes: 256 << 20, Processes: 4})
	got := runContained(t, backend, c, job, d["scratch"], "escape", args)
	for p, want := range probes {
		r, ok := got[p]
		if !ok {
			t.Errorf("%s: no result", p)
			continue
		}
		success := r == "ok" || r == "child ok"
		if success != want {
			t.Errorf("%s: %s (expected success %v)", p, r, want)
		}
	}
	if acc, _ := job.Accounting(); acc.TotalProcesses < 2 {
		t.Errorf("job processes = %d, want the backend and its child", acc.TotalProcesses)
	}
}

// runContained starts backend in the AppContainer and job, waits for its
// JSON line and returns it.
func runContained(t *testing.T, backend string, c *Container, job *Job, scratch, mode string, args []string) map[string]string {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	env := []string{helperEnv + "=" + mode, "TEMP=" + scratch, "TMP=" + scratch}
	p, err := Start(StartOptions{Path: backend, Args: args, Env: env, Dir: scratch, Stdin: inR, Stdout: outW, Stderr: outW, Job: job, Container: c})
	inR.Close()
	outW.Close()
	defer inW.Close()
	if err != nil {
		t.Fatal(err)
	}
	if sid, err := ProcessAppContainer(uint32(p.Pid)); err != nil || sid == nil || !sid.Equals(c.SID) {
		t.Errorf("backend token AppContainer SID = %v, %v; want %s", sid, err, c.SID)
	}
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(bufio.NewReader(outR))
		done <- string(b)
	}()
	var out string
	select {
	case out = <-done:
	case <-time.After(60 * time.Second):
		_ = job.Terminate(1)
		t.Fatal("backend did not finish")
	}
	_, _ = p.Wait()
	var m map[string]string
	line := strings.TrimSpace(out)
	if i := strings.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("backend output %q: %v", out, err)
	}
	return m
}

// TestWindowsGrantsFollowAndRevoke: the AppContainer SID's entries on a
// path follow a changed grant, are inherited by existing files, and are all
// removed on revoke, including the inherited ones (SR-4.6-2).
func TestWindowsGrantsFollowAndRevoke(t *testing.T) {
	reqtest.Partial(t, "SR-4.6-2")
	c := testProfile(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "sub", "f.txt")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(path string, wantMask uint32, inherited bool) {
		t.Helper()
		es, err := Entries(path, c.SID)
		if err != nil {
			t.Fatal(err)
		}
		if wantMask == 0 {
			if len(es) != 0 {
				t.Fatalf("%s: entries remain %+v", path, es)
			}
			return
		}
		if len(es) != 1 || es[0].Mask&wantMask != wantMask || !es[0].Allowed || es[0].Inherited != inherited {
			t.Fatalf("%s: entries %+v, want one allowed mask %#x inherited %v", path, es, wantMask, inherited)
		}
		if wantMask == uint32(ReadExecute.mask()) && es[0].Mask&uint32(windows.FILE_WRITE_DATA) != 0 {
			t.Fatalf("%s: read-only grant allows writing: %#x", path, es[0].Mask)
		}
	}
	if err := Grant(dir, c.SID, Modify); err != nil {
		t.Fatal(err)
	}
	check(dir, uint32(Modify.mask()), false)
	check(file, uint32(Modify.mask()), true)
	if err := Grant(dir, c.SID, ReadExecute); err != nil {
		t.Fatal(err)
	}
	check(dir, uint32(ReadExecute.mask()), false)
	check(file, uint32(ReadExecute.mask()), true)
	if err := Revoke(dir, c.SID); err != nil {
		t.Fatal(err)
	}
	check(dir, 0, false)
	check(file, 0, false)
}

// TestWindowsProfileNames: the profile of a revision is stable and distinct
// per revision, and its SID is the same whether opened or created.
func TestWindowsProfileNames(t *testing.T) {
	reqtest.Partial(t, "FR-21.13", "SR-4.1-3")
	a, b := ProfileName("io.example.files", "1.0.0"), ProfileName("io.example.files", "1.0.1")
	if a == b || len(a) > 64 || a != ProfileName("io.example.files", "1.0.0") {
		t.Fatalf("names %q %q", a, b)
	}
	c := testProfile(t)
	o, err := OpenProfile(c.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !o.SID.Equals(c.SID) {
		t.Fatalf("derived SID %s != created %s", o.SID, c.SID)
	}
	again, err := CreateProfile(c.Name, "again")
	if err != nil || !again.SID.Equals(c.SID) {
		t.Fatalf("create existing: %v %v", again, err)
	}
	other, err := OpenProfile(ProfileName("x", "1"))
	if err != nil || other.SID.Equals(c.SID) {
		t.Fatalf("distinct revision shares a SID: %v", err)
	}
	fmt.Println("profile SID", c.SID)
}
