package bundle

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func writeWheels(t *testing.T, dir string, files map[string]string) []contextforge.LockedFile {
	t.Helper()
	var set []contextforge.LockedFile
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		set = append(set, contextforge.LockedFile{File: name, SHA256: packaging.SHA256Hex([]byte(body)), URL: "https://files.pythonhosted.org/x/" + name})
	}
	return set
}

// TestCheckWheelDir: a wheel directory is accepted only when it holds
// exactly the lock's set; a replaced wheel, an unlisted wheel, another
// file and a missing wheel are refused naming the file (FR-22.20, in part:
// TestWheelSetInstallImage installs the real set).
func TestCheckWheelDir(t *testing.T) {
	reqtest.Partial(t, "FR-22.20")
	dir := t.TempDir()
	set := writeWheels(t, dir, map[string]string{"a-1.0-py3-none-any.whl": "a", "b-2.0-cp312-cp312-linux_x86_64.whl": "b"})
	if err := CheckWheelDir(dir, set); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(d string){
		"b-2.0-cp312-cp312-linux_x86_64.whl": func(d string) {
			_ = os.WriteFile(filepath.Join(d, "b-2.0-cp312-cp312-linux_x86_64.whl"), []byte("evil"), 0o600)
		},
		"extra-0.1-py3-none-any.whl": func(d string) { _ = os.WriteFile(filepath.Join(d, "extra-0.1-py3-none-any.whl"), []byte("x"), 0o600) },
		"setup.py":                   func(d string) { _ = os.WriteFile(filepath.Join(d, "setup.py"), []byte("x"), 0o600) },
		"a-1.0-py3-none-any.whl":     func(d string) { _ = os.Remove(filepath.Join(d, "a-1.0-py3-none-any.whl")) },
	}
	for name, mutate := range cases {
		d := t.TempDir()
		writeWheels(t, d, map[string]string{"a-1.0-py3-none-any.whl": "a", "b-2.0-cp312-cp312-linux_x86_64.whl": "b"})
		mutate(d)
		err := CheckWheelDir(d, set)
		if packaging.ReasonOf(err) != ReasonWheelRefused || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestWheelSetDigest: the digest of the managed-process form changes with
// any wheel of the set, and verification records match only their set.
func TestWheelSetDigest(t *testing.T) {
	lock := contextforge.ReleaseLock().ContextForge
	d := lock.WheelSetDigest("linux/amd64")
	if !strings.HasPrefix(d, "sha256:") || d == lock.WheelSetDigest("linux/arm64") || lock.WheelSetDigest("windows/arm64") != "" {
		t.Fatalf("digests %s", d)
	}
	v := &Verification{Version: lock.Version, Platform: ManagedPlatform, WheelPlatform: "linux/amd64", PlatformDigest: d, Issuer: lock.Signer.Issuer}
	if !v.Matches(&lock, ManagedPlatform) {
		t.Fatal("record of the set does not match")
	}
	other := lock
	other.Wheels = map[string][]contextforge.LockedFile{"linux/amd64": append([]contextforge.LockedFile(nil), lock.Wheels["linux/amd64"]...)}
	other.Wheels["linux/amd64"][0].SHA256 = strings.Repeat("0", 64)
	if v.Matches(&other, ManagedPlatform) {
		t.Fatal("a record matches a changed wheel set")
	}
}

// netBlocker returns a command prefix that runs a command without network
// access (a new, empty network namespace) and whether one is available.
func netBlocker() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	if err := exec.Command("unshare", "--user", "--map-root-user", "--net", "true").Run(); err != nil {
		return nil
	}
	return []string{"unshare", "--user", "--map-root-user", "--net"}
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		in, err := os.Open(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.Create(filepath.Join(dst, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(out, in)
		in.Close()
		out.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// TestWheelSetInstallImage installs the managed-process form from the
// release lock's wheel set (SMCP_CONTEXTFORGE_IMAGE=1; needs CPython 3.12
// as SMCP_CONTEXTFORGE_PYTHON or python3.12 on PATH, and fetches the set
// first). The install runs from a wheel directory with networking
// blocked (a new network namespace on Linux); a directory with one wheel
// replaced and one with an extra unlisted wheel are refused naming the
// wheel, and nothing is installed from them (FR-22.20).
func TestWheelSetInstallImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to install the pinned wheel set")
	}
	py := os.Getenv("SMCP_CONTEXTFORGE_PYTHON")
	if py == "" {
		py, _ = exec.LookPath("python3.12")
	}
	if py == "" {
		t.Skip("no CPython 3.12 (SMCP_CONTEXTFORGE_PYTHON)")
	}
	lock := contextforge.ReleaseLock().ContextForge
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	probe := WheelVerifier{Python: py}
	plat, err := probe.InterpreterPlatform(ctx, lock.Python)
	if err != nil {
		t.Skip(err)
	}
	set := lock.Wheels[plat]
	wheels := t.TempDir()
	if err := FetchWheels(ctx, &http.Client{Timeout: 10 * time.Minute}, wheels, set); err != nil {
		t.Fatal(err)
	}
	blocker := netBlocker()
	blocked := len(blocker) > 0
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		argv := append(append(append([]string(nil), blocker...), name), args...)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // test
		cmd.Env = append(pipEnv(), "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "NO_PROXY=")
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if blocked {
		if out, err := run(ctx, py, "-I", "-c", "import socket; socket.create_connection(('1.1.1.1', 443), timeout=3)"); err == nil {
			t.Fatalf("network reachable inside the blocker: %s", out)
		}
		reqtest.Verifies(t, "FR-22.20")
	} else {
		// Without a network namespace pip still gets no index and a dead
		// proxy, but a direct connection is not prevented.
		t.Log("no network namespace available: networking blocked only by --no-index and a dead proxy")
		reqtest.Partial(t, "FR-22.20")
	}
	root := t.TempDir()
	v := WheelVerifier{Python: py, WheelDir: wheels, Root: root, Run: run}

	// One wheel replaced.
	bad := copyDir(t, wheels)
	victim := set[len(set)/2].File
	if err := os.WriteFile(filepath.Join(bad, victim), []byte("PK\x03\x04 not the wheel"), 0o600); err != nil {
		t.Fatal(err)
	}
	vb := v
	vb.WheelDir = bad
	if _, err := vb.Verify(ctx, &lock, ManagedPlatform, time.Now()); packaging.ReasonOf(err) != ReasonWheelRefused || !strings.Contains(err.Error(), victim) {
		t.Fatalf("replaced wheel: %v", err)
	}
	// An extra unlisted wheel.
	extra := copyDir(t, wheels)
	if err := os.WriteFile(filepath.Join(extra, "evil-1.0-py3-none-any.whl"), []byte("PK\x03\x04"), 0o600); err != nil {
		t.Fatal(err)
	}
	ve := v
	ve.WheelDir = extra
	if _, err := ve.Verify(ctx, &lock, ManagedPlatform, time.Now()); packaging.ReasonOf(err) != ReasonWheelRefused || !strings.Contains(err.Error(), "evil-1.0-py3-none-any.whl") {
		t.Fatalf("extra wheel: %v", err)
	}
	if _, err := os.Stat(VenvDir(root, lock.Version)); !os.IsNotExist(err) {
		t.Fatalf("an environment was created from a refused directory: %v", err)
	}
	// The listed set installs.
	start := time.Now()
	ver, err := v.Verify(ctx, &lock, ManagedPlatform, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed %d wheels for %s in %s (network blocked: %v)", len(set), plat, time.Since(start).Round(time.Second), blocked)
	if !ver.Matches(&lock, ManagedPlatform) || ver.WheelPlatform != plat || ver.PlatformDigest != lock.WheelSetDigest(plat) {
		t.Fatalf("verification %+v", ver)
	}
	if err := v.LocalDigestOK(ctx, ver, ""); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(VenvDir(root, lock.Version)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("environment mode: %v %v", fi, err)
	}
	out, err := run(ctx, VenvPython(root, lock.Version), "-I", "-m", "pip", "freeze", "--all")
	if err != nil {
		t.Fatalf("pip freeze: %v %s", err, out)
	}
	// Every installed distribution comes from a file of the set.
	if n := strings.Count(out, " @ file://"); n != len(set) || !strings.Contains(out, "mcp_contextforge_gateway-"+strings.TrimPrefix(lock.Version, "v")+"-py3-none-any.whl") {
		t.Fatalf("installed %d distributions from files, want %d with ContextForge", n, len(set))
	}
}
