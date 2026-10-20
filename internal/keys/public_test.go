package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestPublishPublic: the CA trust bundle and the view are copied to the
// public directory with mode 0644, rewritten only when they change, follow
// a CA rotation, and never include a private key; a missing directory is
// an error, not created.
func TestPublishPublic(t *testing.T) {
	state := t.TempDir()
	if err := Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "public")
	view := map[string]string{"mcp_url": "https://127.0.0.1:8443/mcp"}
	if _, err := PublishPublic(state, pub, view); err == nil {
		t.Fatal("published into a directory that does not exist")
	}
	if _, err := os.Stat(pub); err == nil {
		t.Fatal("PublishPublic created the directory")
	}
	if err := os.Mkdir(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	wrote, err := PublishPublic(state, pub, view)
	if err != nil || !wrote {
		t.Fatalf("first publish: %v %v", wrote, err)
	}
	ca, _ := os.ReadFile(filepath.Join(state, CACertFile))
	got, _ := os.ReadFile(filepath.Join(pub, publicCAFile))
	if !bytes.Equal(ca, got) {
		t.Fatal("published CA differs from the trust bundle")
	}
	v, _ := os.ReadFile(filepath.Join(pub, publicViewFile))
	if !strings.Contains(string(v), "https://127.0.0.1:8443/mcp") {
		t.Fatalf("view %s", v)
	}
	for _, f := range []string{publicCAFile, publicViewFile} {
		b, _ := os.ReadFile(filepath.Join(pub, f))
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatalf("%s holds a private key", f)
		}
		if runtime.GOOS != "windows" {
			if st, _ := os.Stat(filepath.Join(pub, f)); st.Mode().Perm() != 0o644 {
				t.Fatalf("%s mode %v", f, st.Mode())
			}
		}
	}
	if wrote, err := PublishPublic(state, pub, view); err != nil || wrote {
		t.Fatalf("unchanged publish wrote: %v %v", wrote, err)
	}
	// A CA rotation publishes the bundle with both CAs, then the new one.
	if _, _, err := BeginCARotation(state, time.Now(), time.Hour, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if wrote, err := PublishPublic(state, pub, view); err != nil || !wrote {
		t.Fatalf("publish after rotation start: %v %v", wrote, err)
	}
	got, _ = os.ReadFile(filepath.Join(pub, publicCAFile))
	if n := strings.Count(string(got), "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("published bundle during the overlap has %d certificates, want 2", n)
	}
}
