package bundle

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// fakeProc serves /health on the port of the spec it was started with.
type fakeProc struct {
	srv  *http.Server
	done chan struct{}
	once sync.Once
}

func (f *fakeProc) Done() <-chan struct{} { return f.done }
func (f *fakeProc) Stop(time.Duration) error {
	f.once.Do(func() { _ = f.srv.Close(); close(f.done) })
	return nil
}

// TestManagedProcess: the managed-process form starts the interpreter of
// the configured environment with uvicorn on 127.0.0.1 and a fresh port,
// in its private working directory with D-16 inside it, with the doubled
// CP-24 limits for the Job Object, and with an environment made only of
// the generated configuration and the credentials: none of the Gateway's
// own variables. It becomes healthy, and Stop ends it (FR-22.25, SR-2.14-1).
func TestManagedProcess(t *testing.T) {
	reqtest.Partial(t, "FR-22.25", "FR-22.26")
	t.Setenv("SMCP_SHOULD_NOT_LEAK", "gateway-variable")
	creds, _ := NewCredentials()
	dir := t.TempDir()
	var mu sync.Mutex
	var specs []winsandbox.ManagedSpec
	start := func(s winsandbox.ManagedSpec) (ManagedProc, error) {
		mu.Lock()
		specs = append(specs, s)
		mu.Unlock()
		port := s.Args[slices.Index(s.Args, "--port")+1]
		l, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			return nil, err
		}
		f := &fakeProc{done: make(chan struct{}), srv: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				w.WriteHeader(http.StatusNotFound)
			}
		}), ReadHeaderTimeout: time.Second}}
		go func() { _ = f.srv.Serve(l) }()
		return f, nil
	}
	python := filepath.Join(dir, "venv", "bin", "python")
	if runtime.GOOS == "windows" {
		python = filepath.Join(dir, "venv", "Scripts", "python.exe")
	}
	if _, err := NewProcess(ProcessOptions{Python: "python", Dir: dir, Credentials: func() (Credentials, error) { return creds, nil }}); err == nil {
		t.Fatal("a relative interpreter path was accepted")
	}
	p, err := NewProcess(ProcessOptions{Python: python, Dir: filepath.Join(dir, "instance"), Settings: Settings{Limits: testLimits},
		Credentials: func() (Credentials, error) { return creds, nil }, Start: start, HealthInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	p.SetSSRFAllowed([]string{"127.0.0.1/32"})
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	waitFor(t, "healthy", p.Healthy)
	if !strings.HasPrefix(p.BaseURL(), "http://127.0.0.1:") || !p.Running() {
		t.Fatalf("base %q", p.BaseURL())
	}
	mu.Lock()
	s := specs[0]
	mu.Unlock()
	if s.Path != python || s.Dir != filepath.Join(dir, "instance") || strings.Join(s.Args[:3], " ") != "-m uvicorn mcpgateway.main:app" ||
		s.Args[4] != "127.0.0.1" {
		t.Fatalf("spec %+v", s)
	}
	if s.Limits.MemoryBytes != 1024<<20 || s.Limits.CPUs != 2 || s.Limits.Processes != 256 {
		t.Fatalf("limits %+v", s.Limits)
	}
	if st, err := os.Stat(filepath.Join(dir, "instance", "data")); err != nil || !st.IsDir() {
		t.Fatalf("D-16 directory: %v", err)
	}
	want := Environment(Settings{SSRFAllowed: []string{"127.0.0.1/32"}, Limits: testLimits})
	for k, v := range creds {
		want[k] = v
	}
	for _, kv := range s.Env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "HOST":
			if v != "127.0.0.1" {
				t.Fatalf("HOST=%s", v)
			}
		case "PORT", "DATABASE_URL":
		case "SYSTEMROOT":
			if runtime.GOOS != "windows" {
				t.Fatal("SYSTEMROOT off Windows")
			}
		default:
			if w, ok := want[k]; !ok || w != v {
				t.Fatalf("variable %s is not generated configuration or a credential", k)
			}
		}
	}
	if strings.Contains(strings.Join(s.Env, "\n"), "gateway-variable") {
		t.Fatal("a Gateway variable reached the process")
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.Status().State != StateStopped || p.BaseURL() != "" || p.Running() {
		t.Fatalf("after stop %+v", p.Status())
	}
}
