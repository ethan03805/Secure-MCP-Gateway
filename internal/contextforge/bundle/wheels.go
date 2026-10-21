package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// The managed-process installation of SRS FR-22.20: the bundled instance
// is installed into a private virtual environment under the Gateway's
// state directory (owned by the Gateway's identity, mode 0700) from the
// wheel set of the release lock, every wheel's SHA-256 checked before pip
// sees it. The wheels come from an operator-supplied directory
// ([contextforge] wheel_dir) or are fetched from their PyPI URLs in the
// lock into <state>/contextforge/wheels; either way the directory must
// hold exactly the platform's set. pip then installs from that directory
// only (--no-index --no-deps --require-hashes), so it neither resolves
// nor fetches anything.

// ReasonWheelRefused: a wheel directory holds a wheel or file the release
// lock does not list, a wheel whose SHA-256 differs, or lacks a listed
// wheel (FR-22.20).
const ReasonWheelRefused = "CONTEXTFORGE_WHEEL_REFUSED"

// ReasonPythonUnsupported: the base interpreter is not CPython at the
// lock's version on a platform the lock pins a wheel set for.
const ReasonPythonUnsupported = "CONTEXTFORGE_PYTHON_UNSUPPORTED"

// wheelSetFile is the record of the installed wheel set inside a virtual
// environment.
const wheelSetFile = "smcp-wheelset.json"

// VenvDir is the private virtual environment of a ContextForge version
// under root (<state>/contextforge/instance).
func VenvDir(root, version string) string { return filepath.Join(root, "venv-"+version) }

// VenvPython is the interpreter of the virtual environment of version.
func VenvPython(root, version string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(VenvDir(root, version), "Scripts", "python.exe")
	}
	return filepath.Join(VenvDir(root, version), "bin", "python")
}

// CheckWheelDir confirms that dir holds exactly the wheel set: every
// listed wheel with its SHA-256 and nothing else. The refusal names the
// wheel or file.
func CheckWheelDir(dir string, set []contextforge.LockedFile) error {
	want := map[string]string{}
	for _, w := range set {
		want[w.File] = w.SHA256
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return packaging.Wrap(ReasonWheelRefused, "reading the wheel directory", err)
	}
	seen := map[string]bool{}
	for _, e := range ents {
		name := e.Name()
		sum, listed := want[name]
		if !listed || !e.Type().IsRegular() {
			return packaging.Errf(ReasonWheelRefused, "%s is not a wheel of the release lock's set", name)
		}
		got, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			return packaging.Wrap(ReasonWheelRefused, "reading "+name, err)
		}
		if got != sum {
			return packaging.Errf(ReasonWheelRefused, "%s has SHA-256 %s; the release lock lists %s", name, got, sum)
		}
		seen[name] = true
	}
	var missing []string
	for name := range want {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return packaging.Errf(ReasonWheelRefused, "the wheel directory lacks %d wheels of the release lock, for example %s", len(missing), missing[0])
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FetchWheels downloads every wheel of the set that dir lacks from its URL
// in the release lock. A download is written beside its final name and
// renamed only when its SHA-256 matches.
func FetchWheels(ctx context.Context, client *http.Client, dir string, set []contextforge.LockedFile) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, w := range set {
		path := filepath.Join(dir, w.File)
		if got, err := fileSHA256(path); err == nil && got == w.SHA256 {
			continue
		}
		if err := fetchWheel(ctx, client, path, w); err != nil {
			return err
		}
	}
	return nil
}

func fetchWheel(ctx context.Context, client *http.Client, path string, w contextforge.LockedFile) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return packaging.Wrap(ReasonWheelRefused, "fetching "+w.File, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return packaging.Errf(ReasonWheelRefused, "fetching %s: HTTP %d", w.File, resp.StatusCode)
	}
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 256<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return packaging.Wrap(ReasonWheelRefused, "fetching "+w.File, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != w.SHA256 {
		_ = os.Remove(tmp)
		return packaging.Errf(ReasonWheelRefused, "%s from %s has SHA-256 %s; the release lock lists %s", w.File, w.URL, got, w.SHA256)
	}
	return os.Rename(tmp, path)
}

// WheelVerifier installs and checks the managed-process form (FR-22.20).
// It implements the Connector's ImageVerifier: Verify installs the lock's
// wheel set into a fresh virtual environment of the release's version and
// LocalDigestOK confirms that the environment still records that set.
type WheelVerifier struct {
	// Python is the base interpreter (CPython at the lock's version) that
	// creates the virtual environment.
	Python string
	// WheelDir is the operator's wheel directory ("": fetch into Cache).
	WheelDir string
	Cache    string
	// Root holds the virtual environments (VenvDir).
	Root string
	HTTP *http.Client
	// Run runs a command and returns its combined output; tests replace
	// it.
	Run func(ctx context.Context, name string, args ...string) (string, error)
}

func (v WheelVerifier) run(ctx context.Context, name string, args ...string) (string, error) {
	if v.Run != nil {
		return v.Run(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: the configured interpreter and the venv's own
	cmd.Env = pipEnv()
	out, err := cmd.CombinedOutput()
	if len(out) > 8<<10 {
		out = out[len(out)-8<<10:]
	}
	return strings.TrimSpace(string(out)), err
}

// pipEnv is the environment of the interpreter and pip: no index, proxy
// or configuration file of the Gateway's environment applies.
func pipEnv() []string {
	env := []string{"PIP_NO_INDEX=1", "PIP_DISABLE_PIP_VERSION_CHECK=1", "PIP_CONFIG_FILE=" + os.DevNull, "PYTHONNOUSERSITE=1", "PIP_NO_INPUT=1"}
	for _, k := range []string{"PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA"} {
		if val, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+val)
		}
	}
	return env
}

// InterpreterPlatform returns the wheel platform of the base interpreter
// (linux/amd64, linux/arm64, darwin/arm64 or windows/amd64) and refuses
// another implementation, version or platform.
func (v WheelVerifier) InterpreterPlatform(ctx context.Context, want string) (string, error) {
	out, err := v.run(ctx, v.Python, "-I", "-c", "import platform,sys,sysconfig;print(sys.implementation.name, '%d.%d' % sys.version_info[:2], sysconfig.get_platform(), platform.machine())")
	if err != nil {
		return "", packaging.Wrap(ReasonPythonUnsupported, "running "+v.Python, fmt.Errorf("%w: %s", err, firstLine(out)))
	}
	f := strings.Fields(lastLine(out))
	if len(f) != 4 || f[0] != "cpython" || f[1] != want {
		return "", packaging.Errf(ReasonPythonUnsupported, "%s is %q; the wheel set needs CPython %s", v.Python, lastLine(out), want)
	}
	plat, mach := strings.ToLower(f[2]), strings.ToLower(f[3])
	switch {
	case plat == "linux-x86_64":
		return "linux/amd64", nil
	case plat == "linux-aarch64":
		return "linux/arm64", nil
	case strings.HasPrefix(plat, "macosx-") && (strings.HasSuffix(plat, "-arm64") || (strings.HasSuffix(plat, "-universal2") && mach == "arm64")):
		return "darwin/arm64", nil
	case plat == "win-amd64":
		return "windows/amd64", nil
	}
	return "", packaging.Errf(ReasonPythonUnsupported, "%s runs on %s (%s); the release lock pins wheel sets for %v only (on Windows arm64 use an x64 interpreter)",
		v.Python, f[2], f[3], contextforge.WheelPlatforms)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// wheelSet is the record written into an installed environment.
type wheelSet struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Digest   string `json:"digest"`
}

// Verify implements the Connector's ImageVerifier: it checks the base
// interpreter, takes the wheel directory (the operator's, or the cache
// after fetching the set into it), refuses it unless it holds exactly the
// lock's set, installs the set into a new virtual environment of the
// release and checks the installed version.
func (v WheelVerifier) Verify(ctx context.Context, r *contextforge.LockedRelease, _ string, now time.Time) (*Verification, error) {
	if v.Python == "" || !filepath.IsAbs(v.Python) || v.Root == "" {
		return nil, errors.New("bundle: the managed-process installation needs an absolute base interpreter path and a state directory")
	}
	plat, err := v.InterpreterPlatform(ctx, r.Python)
	if err != nil {
		return nil, err
	}
	set := r.Wheels[plat]
	dir := v.WheelDir
	if dir == "" {
		dir = filepath.Join(v.Cache, r.Version+"-"+strings.ReplaceAll(plat, "/", "-"))
		client := v.HTTP
		if client == nil {
			client = &http.Client{Timeout: 10 * time.Minute}
		}
		if err := FetchWheels(ctx, client, dir, set); err != nil {
			return nil, err
		}
	}
	if err := CheckWheelDir(dir, set); err != nil {
		return nil, err
	}
	if err := v.install(ctx, r, plat, dir, set); err != nil {
		return nil, err
	}
	digest := r.WheelSetDigest(plat)
	wf, _, _ := strings.Cut(strings.TrimPrefix(r.Signer.Subject, r.Source.Repository+"/"), "@")
	return &Verification{Version: r.Version, SourceTag: r.Source.Tag, SourceCommit: r.Source.Commit, Workflow: wf, Issuer: r.Signer.Issuer,
		Platform: ManagedPlatform, WheelPlatform: plat, PlatformDigest: digest, VerifiedAt: now.UTC()}, nil
}

func (v WheelVerifier) install(ctx context.Context, r *contextforge.LockedRelease, plat, dir string, set []contextforge.LockedFile) error {
	venv := VenvDir(v.Root, r.Version)
	if err := os.RemoveAll(venv); err != nil {
		return err
	}
	if err := os.MkdirAll(v.Root, 0o700); err != nil {
		return err
	}
	if out, err := v.run(ctx, v.Python, "-I", "-m", "venv", venv); err != nil {
		return fmt.Errorf("create the virtual environment %s: %w: %s", venv, err, lastLine(out))
	}
	if err := os.Chmod(venv, 0o700); err != nil { //nolint:gosec // G302: a directory, private to the Gateway
		return err
	}
	var req strings.Builder
	for _, w := range set {
		abs, err := filepath.Abs(filepath.Join(dir, w.File))
		if err != nil {
			return err
		}
		fmt.Fprintf(&req, "%s --hash=sha256:%s\n", abs, w.SHA256)
	}
	reqFile := filepath.Join(venv, "smcp-requirements.txt")
	if err := os.WriteFile(reqFile, []byte(req.String()), 0o600); err != nil {
		return err
	}
	py := VenvPython(v.Root, r.Version)
	if out, err := v.run(ctx, py, "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes", "--only-binary", ":all:",
		"--no-compile", "--disable-pip-version-check", "-r", reqFile); err != nil {
		_ = os.RemoveAll(venv)
		return packaging.Wrap(ReasonWheelRefused, "installing the wheel set", fmt.Errorf("%w: %s", err, lastLine(out)))
	}
	out, err := v.run(ctx, py, "-I", "-c", "import importlib.metadata as m; print(m.version('mcp-contextforge-gateway'))")
	if want := strings.TrimPrefix(r.Version, "v"); err != nil || lastLine(out) != want {
		_ = os.RemoveAll(venv)
		return packaging.Errf(ReasonVersionMismatch, "the installed environment holds ContextForge %q; the release lock pins %s", lastLine(out), want)
	}
	return packaging.WriteJSON(filepath.Join(venv, wheelSetFile), wheelSet{Version: r.Version, Platform: plat, Digest: r.WheelSetDigest(plat)}, 0o600)
}

// LocalDigestOK implements the Connector's ImageVerifier: the virtual
// environment of the verified version still records the verified wheel
// set.
func (v WheelVerifier) LocalDigestOK(_ context.Context, ver *Verification, _ string) error {
	raw, err := os.ReadFile(filepath.Join(VenvDir(v.Root, ver.Version), wheelSetFile))
	if err != nil {
		return packaging.Errf(ReasonUnverified, "the virtual environment of ContextForge %s is not installed", ver.Version)
	}
	var ws wheelSet
	if err := json.Unmarshal(raw, &ws); err != nil || ws.Digest != ver.PlatformDigest || ws.Platform != ver.WheelPlatform {
		return packaging.Errf(ReasonUnverified, "the virtual environment of ContextForge %s does not record the verified wheel set", ver.Version)
	}
	if _, err := os.Stat(VenvPython(v.Root, ver.Version)); err != nil {
		return packaging.Errf(ReasonUnverified, "the interpreter of the virtual environment of ContextForge %s is missing", ver.Version)
	}
	return nil
}
