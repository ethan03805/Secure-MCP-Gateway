package bundle

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var testLimits = Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}

// FR-22.27 and FR-22.37 (configuration part): the generated configuration
// passes its check, and altering any one rule is refused naming the key.
// The route behavior of the running instance is TestPinnedImage.
func TestGeneratedConfiguration(t *testing.T) {
	reqtest.Partial(t, "FR-22.27", "FR-22.37")
	env := Environment(Settings{SSRFAllowed: []string{"10.0.2.2/32"}, Limits: testLimits})
	if err := CheckEnvironment(env, testLimits); err != nil {
		t.Fatal(err)
	}
	if env["GUNICORN_WORKERS"] != "1" || env["EMAIL_AUTH_ENABLED"] != "true" || env["PUBLIC_REGISTRATION_ENABLED"] != "false" ||
		env["SSRF_ALLOWED_NETWORKS"] != `["10.0.2.2/32"]` || env["TOOL_TIMEOUT"] != "90" || env["TOOL_RATE_LIMIT"] != "120" || env["TOOL_CONCURRENT_LIMIT"] != "32" {
		t.Fatalf("env %v", env)
	}
	if Environment(Settings{Limits: testLimits})["SSRF_ALLOWED_NETWORKS"] != "[]" {
		t.Fatal("no endpoint must allow no network")
	}
	cases := map[string]func(map[string]string){
		"EMAIL_AUTH_ENABLED":          func(e map[string]string) { e["EMAIL_AUTH_ENABLED"] = "false" },
		"GUNICORN_WORKERS":            func(e map[string]string) { delete(e, "GUNICORN_WORKERS") },
		"PLUGINS_ENABLED":             func(e map[string]string) { e["PLUGINS_ENABLED"] = "true" },
		"MCPGATEWAY_UI_ENABLED":       func(e map[string]string) { delete(e, "MCPGATEWAY_UI_ENABLED") },
		"SSO_GITHUB_ENABLED":          func(e map[string]string) { e["SSO_GITHUB_ENABLED"] = "1" },
		"GATEWAY_TOOL_NAME_SEPARATOR": func(e map[string]string) { e["GATEWAY_TOOL_NAME_SEPARATOR"] = "__" },
		"ALLOWED_ORIGINS":             func(e map[string]string) { e["ALLOWED_ORIGINS"] = "*" },
		"SSRF_ALLOWED_NETWORKS":       func(e map[string]string) { e["SSRF_ALLOWED_NETWORKS"] = `["evil.example"]` },
		"TOOL_TIMEOUT":                func(e map[string]string) { e["TOOL_TIMEOUT"] = "30" }, // below twice CP-13
		"TOOL_RATE_LIMIT":             func(e map[string]string) { e["TOOL_RATE_LIMIT"] = "100" },
		"REQUIRE_JTI":                 func(e map[string]string) { e["REQUIRE_JTI"] = "false" },
		"JWT_SECRET_KEY":              func(e map[string]string) { e["JWT_SECRET_KEY"] = "x" },
	}
	for key, alter := range cases {
		e := Environment(Settings{Limits: testLimits})
		alter(e)
		err := CheckEnvironment(e, testLimits)
		if packaging.ReasonOf(err) != ReasonConfigRefused || !strings.Contains(err.Error(), key) {
			t.Errorf("%s altered: %v", key, err)
		}
	}
}

// FR-22.28 (checks): generated credentials are at least 43 characters of
// 256 random bits; empty, published and short values are refused naming
// the key and never the value.
func TestCredentials(t *testing.T) {
	reqtest.Partial(t, "FR-22.28")
	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Check(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, k := range CredentialKeys {
		if len(c[k]) < MinCredentialChars || seen[c[k]] {
			t.Fatalf("%s: weak or repeated", k)
		}
		seen[c[k]] = true
	}
	for name, v := range map[string]string{"changeme": "changeme", "example placeholder": "my-test-key", "empty": "", "short": strings.Repeat("a", 42)} {
		for _, k := range []string{KeyJWTSecret, KeyDefaultUser} {
			bad := Credentials{}
			for kk, vv := range c {
				bad[kk] = vv
			}
			bad[k] = v
			err := bad.Check()
			if packaging.ReasonOf(err) != ReasonWeakCredential || !strings.Contains(err.Error(), k) {
				t.Errorf("%s %s: %v", k, name, err)
			}
			if v != "" && strings.Contains(err.Error(), v) {
				t.Errorf("%s %s: the error names the value", k, name)
			}
		}
	}
}

func TestAdminTokenClaims(t *testing.T) {
	c, _ := NewCredentials()
	now := time.Unix(1_800_000_000, 0)
	tok, err := AdminToken(c, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal(tok)
	}
	m := hmac.New(sha256.New, []byte(c[KeyJWTSecret]))
	m.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(m.Sum(nil)) != parts[2] {
		t.Fatal("signature does not verify with the JWT key")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var cl map[string]any
	_ = json.Unmarshal(raw, &cl)
	if cl["iss"] != "mcpgateway" || cl["aud"] != "mcpgateway-api" || cl["sub"] != AdminEmail || cl["jti"] == "" || cl["exp"].(float64) != float64(now.Add(time.Minute).Unix()) {
		t.Fatalf("claims %v", cl)
	}
}

// fakeEngine plays a container engine: "run" starts a listener on the
// published loopback port whose /health answers as healthy says; "rm"
// stops it.
type fakeEngine struct {
	mu      sync.Mutex
	runs    int
	healthy atomic.Bool
	srv     *http.Server
	args    [][]string
	vals    []map[string]string
}

func (f *fakeEngine) exec(_ context.Context, vals map[string]string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.args = append(f.args, args)
	f.vals = append(f.vals, vals)
	switch args[0] {
	case "volume":
		return "", nil
	case "rm":
		if f.srv != nil {
			_ = f.srv.Close()
			f.srv = nil
		}
		return "", nil
	case "run":
		if args[1] == "--rm" { // the volume preparation
			return "", nil
		}
		f.runs++
		var addr string
		for i, a := range args {
			if a == "-p" {
				addr = strings.TrimSuffix(args[i+1], ":4444")
			}
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return "", err
		}
		f.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" && f.healthy.Load() {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		}), ReadHeaderTimeout: time.Second}
		go func() { _ = f.srv.Serve(l) }()
		return "cid", nil
	}
	return "", nil
}

func (f *fakeEngine) runCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.runs }

func newFakeInstance(t *testing.T, f *fakeEngine, creds Credentials) (*Instance, *[]string) {
	t.Helper()
	var mu sync.Mutex
	states := []string{}
	in, err := New(Options{Engine: Engine{Path: "docker"}, Image: "ghcr.io/ibm/mcp-context-forge@sha256:" + strings.Repeat("a", 64), Name: "smcp-cf-test",
		Settings: Settings{Limits: testLimits}, Credentials: func() (Credentials, error) { return creds, nil },
		HealthWait: 400 * time.Millisecond, HealthInterval: 50 * time.Millisecond, Failures: 3,
		OnState: func(s, _ string) { mu.Lock(); states = append(states, s); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	in.exec = f.exec
	t.Cleanup(func() { _ = in.Stop(context.Background()) })
	return in, &states
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// FR-22.30 (supervision): starting until the first /health answer, a
// restart when none comes within the health wait, a restart after three
// failed checks while running, and recovery. FR-22.26 (part): the port is
// on 127.0.0.1 and new at each start. FR-22.28 (part): credentials reach the
// engine only through its environment, never its arguments.
func TestSupervision(t *testing.T) {
	reqtest.Partial(t, "FR-22.30", "FR-22.26", "FR-22.28")
	creds, _ := NewCredentials()
	f := &fakeEngine{}
	in, states := newFakeInstance(t, f, creds)
	if err := in.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := in.Status(); st.State != StateStarting || st.Port == 0 {
		t.Fatalf("after start: %+v", st)
	}
	// Never healthy: restarted after the health wait, on a new port.
	first := in.Status().Port
	waitFor(t, "a restart", func() bool { return f.runCount() >= 2 })
	f.healthy.Store(true)
	waitFor(t, "healthy", in.Healthy)
	if in.Status().Port == first && f.runCount() == 2 {
		t.Log("the restart reused the port by chance")
	}
	// Three failed checks: unhealthy, restarted, healthy again.
	runs := f.runCount()
	f.healthy.Store(false)
	waitFor(t, "unhealthy", func() bool { return in.Status().State != StateHealthy })
	waitFor(t, "a restart after failures", func() bool { return f.runCount() > runs })
	f.healthy.Store(true)
	waitFor(t, "recovery", in.Healthy)
	if err := in.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if in.Status().State != StateStopped || in.BaseURL() != "" {
		t.Fatalf("after stop: %+v", in.Status())
	}
	got := strings.Join(*states, ",")
	for _, want := range []string{StateStarting, StateHealthy, StateUnhealthy, StateStopped} {
		if !strings.Contains(got, want) {
			t.Errorf("states %s lack %s", got, want)
		}
	}
	// Credentials: names in the arguments, values only in the environment.
	f.mu.Lock()
	defer f.mu.Unlock()
	for n, args := range f.args {
		joined := strings.Join(args, " ")
		for _, k := range CredentialKeys {
			if strings.Contains(joined, creds[k]) {
				t.Fatalf("a credential value is in the engine arguments")
			}
		}
		if args[0] == "run" && args[1] != "--rm" {
			if !strings.Contains(joined, "-e "+KeyJWTSecret+" ") || f.vals[n][KeyJWTSecret] != creds[KeyJWTSecret] {
				t.Fatalf("credential not passed by name: %s", joined)
			}
			for _, flag := range []string{"-p 127.0.0.1:", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--memory 1024m", "--cpus 2", "--pids-limit 256"} {
				if !strings.Contains(joined, flag) {
					t.Errorf("run lacks %q: %s", flag, joined)
				}
			}
		}
	}
}

// A start with weak credentials is refused before anything runs.
func TestStartRefusesWeakCredentials(t *testing.T) {
	reqtest.Partial(t, "FR-22.28")
	creds, _ := NewCredentials()
	creds[KeyJWTSecret] = "changeme"
	f := &fakeEngine{}
	in, _ := newFakeInstance(t, f, creds)
	if err := in.Start(context.Background()); packaging.ReasonOf(err) != ReasonWeakCredential {
		t.Fatalf("start: %v", err)
	}
	if f.runCount() != 0 {
		t.Fatal("the container ran")
	}
}

func TestNewRefusesUnpinnedImage(t *testing.T) {
	if _, err := New(Options{Engine: Engine{Path: "docker"}, Image: "ghcr.io/ibm/mcp-context-forge:latest", Name: "x",
		Credentials: func() (Credentials, error) { return nil, nil }}); err == nil {
		t.Fatal("tag accepted")
	}
}

func TestNewCredentialAvoidsSequences(t *testing.T) {
	for _, bad := range []string{"xxabcxx", "xxaBcxx", "xx321xx", "xxZYXxx"} {
		if !sequential(bad) {
			t.Errorf("%q not seen as sequential", bad)
		}
	}
	if sequential("a1b2c3") {
		t.Error("a1b2c3 seen as sequential")
	}
	for i := 0; i < 2000; i++ {
		v, err := NewCredential()
		if err != nil || sequential(v) || len(v) < MinCredentialChars {
			t.Fatalf("credential %d: %v", i, err)
		}
	}
}
