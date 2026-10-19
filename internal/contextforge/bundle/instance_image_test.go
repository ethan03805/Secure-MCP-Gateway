package bundle

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestPinnedImage runs the pinned ContextForge image (about 600 MB, so only
// when SMCP_CONTEXTFORGE_IMAGE=1 and Docker or Podman is installed): it
// starts with the generated configuration and credentials on a loopback
// port, answers /health within the CP-47 wait, accepts the administrator
// token on /v1/tokens, refuses public registration, every disabled route
// family and a token signed with a published key, runs one worker process,
// and is removed by Stop.
func TestPinnedImage(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to run the pinned ContextForge image")
	}
	reqtest.Partial(t, "FR-22.26", "FR-22.27", "FR-22.28", "FR-22.30", "FR-22.37")
	eng, err := FindEngine()
	if err != nil {
		t.Skip(err)
	}
	creds, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	img := contextforge.ReleaseLock().ContextForge.ImageRef("linux/" + runtime.GOARCH)
	name := "smcp-cf-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	in, err := New(Options{Engine: eng, Image: img, Name: name,
		Settings:    Settings{Limits: Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}},
		Credentials: func() (Credentials, error) { return creds, nil }, HealthWait: 120 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		_ = in.Stop(ctx)
		_ = in.RemoveVolume(ctx)
	})
	start := time.Now()
	if err := in.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for !in.Healthy() {
		if time.Since(start) > 120*time.Second {
			out, _ := exec.Command(eng.Path, "logs", "--tail", "40", name).CombinedOutput()
			t.Fatalf("not healthy after %v: %+v\n%s", time.Since(start), in.Status(), redactOutput(string(out), creds))
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Logf("healthy after %v (FR-22.30 expects about 15 s, at most 60 s)", time.Since(start).Round(time.Second))

	base := in.BaseURL()
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatalf("base URL %s", base)
	}
	// FR-22.26: published on loopback only.
	out, err := exec.Command(eng.Path, "port", name).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "127.0.0.1:") || strings.Contains(string(out), "0.0.0.0") || strings.Contains(string(out), "[::]") {
		t.Fatalf("published ports: %s %v", out, err)
	}
	do := func(method, path, token string) int {
		body := "{}"
		if path == "/v1/auth/email/register" {
			body = `{"email":"someone@example.com","password":"Long-Enough-Passw0rd!","full_name":"Someone"}`
		}
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	admin, err := in.AdminToken(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st := do("GET", "/v1/tokens", admin); st != http.StatusOK {
		t.Fatalf("/v1/tokens with the administrator token: %d", st)
	}
	if st := do("GET", "/v1/teams", admin); st != http.StatusOK {
		t.Fatalf("/v1/teams with the administrator token: %d", st)
	}
	// HFC-14 (part): a token signed with a published key is refused.
	forged, _ := SignJWT("my-test-key", map[string]any{"sub": AdminEmail, "iss": "mcpgateway", "aud": "mcpgateway-api",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "x", "token_use": "session"})
	if st := do("GET", "/v1/tokens", forged); st != http.StatusUnauthorized && st != http.StatusForbidden {
		t.Fatalf("forged token: %d", st)
	}
	if st := do("POST", "/v1/auth/email/register", ""); st != http.StatusForbidden && st != http.StatusNotFound {
		t.Fatalf("public registration: %d", st)
	}
	// Route families of the disabled features (FR-22.27).
	for _, p := range []string{"GET /admin/", "GET /v1/catalog", "GET /llmchat/status", "GET /v1/a2a", "GET /reverse-proxy/sessions",
		"GET /ws", "POST /tools/preview/x", "POST /v1/tools/bulk", "GET /auth/sso/providers"} {
		m, path, _ := strings.Cut(p, " ")
		if st := do(m, path, admin); st != http.StatusNotFound && st != http.StatusForbidden && st != http.StatusMethodNotAllowed {
			t.Errorf("%s with the administrator token: %d, want 404 or 403", p, st)
		}
	}
	// One worker process (FR-22.27): gunicorn's master and one worker.
	top, err := exec.Command(eng.Path, "top", name).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if n := gunicornWorkers(string(top)); n != 1 || !strings.Contains(string(top), "--workers 1") {
		t.Errorf("%d gunicorn worker processes, want one:\n%s", n, top)
	}
	if err := in.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(eng.Path, "inspect", name).CombinedOutput(); err == nil {
		t.Fatalf("container still exists after Stop: %s", out)
	}
}

// gunicornWorkers counts the gunicorn processes whose parent is the
// gunicorn master (the gunicorn process whose parent is not gunicorn) in
// the output of `docker top` (UID PID PPID ...).
func gunicornWorkers(top string) int {
	parent := map[string]string{}
	for _, line := range strings.Split(top, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.Contains(line, "gunicorn") {
			continue
		}
		parent[f[1]] = f[2]
	}
	n := 0
	for _, pp := range parent {
		if gp, ok := parent[pp]; ok {
			if _, nested := parent[gp]; !nested {
				n++
			}
		}
	}
	return n
}
