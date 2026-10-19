package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// SR-2.13-5 (vault part) and FR-22.28 (holding): the bundled ContextForge
// credentials are vault entries, encrypted at rest, delivered only to
// their component with evidence and never to a server; the component
// namespace cannot be created through the ordinary path.
func TestComponentCredentials(t *testing.T) {
	reqtest.Partial(t, "SR-2.13-5", "FR-22.28")
	tv := newTestVault(t)
	b, err := NewBroker(BrokerOptions{Vault: tv.v, Use: &UseSet{}, RuntimeDir: filepath.Join(t.TempDir(), "run")})
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	b.AttachEvidence(mem)
	value := []byte("generated-credential-value-0123456789-abcdefgh")
	created, err := b.EnsureComponent("contextforge", "jwt-secret-key", func() ([]byte, error) { return bytes.Clone(value), nil })
	if err != nil || !created {
		t.Fatalf("ensure: %v %v", created, err)
	}
	created, err = b.EnsureComponent("contextforge", "jwt-secret-key", func() ([]byte, error) { t.Fatal("regenerated"); return nil, nil })
	if err != nil || created {
		t.Fatalf("second ensure: %v %v", created, err)
	}
	// Encrypted at rest.
	if raw, err := os.ReadFile(filepath.Join(tv.dir, StoreFile)); err != nil || bytes.Contains(raw, value) {
		t.Fatalf("vault store holds the value in clear (%v)", err)
	}
	got, err := b.DeliverComponent("contextforge", []string{"jwt-secret-key"})
	if err != nil || !bytes.Equal(got["jwt-secret-key"], value) {
		t.Fatalf("deliver: %v", err)
	}
	var use audit.Event
	for _, e := range mem.Events() {
		if e.Class == "secret_use" {
			use = e
		}
	}
	d, _ := use.Detail.(map[string]any)
	if use.Outcome != "delivered" || d["component"] != "contextforge" || strings.Contains(strings.Join(eventStrings(use), " "), string(value)) {
		t.Fatalf("secret_use event %+v", use)
	}
	if len(b.Fingerprints().Scan(append([]byte("result: "), value...))) == 0 {
		t.Fatal("no leak fingerprint registered for the delivered credential")
	}
	// Another component, the ordinary create path and a server binding
	// are refused.
	if _, err := b.DeliverComponent("other", []string{"jwt-secret-key"}); err == nil {
		t.Fatal("another component received the credential")
	}
	if _, err := tv.v.Create("admin", CreateParams{Name: ComponentName("contextforge", "x"), Value: []byte("value-value-value")}); !errors.Is(err, ErrComponentName) {
		t.Fatalf("create in the component namespace: %v", err)
	}
	if _, err := tv.v.open(ComponentName("contextforge", "jwt-secret-key"), 0); !errors.Is(err, ErrComponentName) {
		t.Fatalf("server delivery path opened a component credential: %v", err)
	}
	if reasonFor(ErrComponentName) != ReasonNotGranted {
		t.Fatal("component credentials must be refused to servers as not granted")
	}
	// Rotation and retirement.
	if err := b.RotateComponent("contextforge", "jwt-secret-key", func() ([]byte, error) { return []byte("rotated-credential-value-0123456789-abcdefgh"), nil }); err != nil {
		t.Fatal(err)
	}
	got, _ = b.DeliverComponent("contextforge", []string{"jwt-secret-key"})
	if string(got["jwt-secret-key"]) != "rotated-credential-value-0123456789-abcdefgh" {
		t.Fatal("rotation not delivered")
	}
	if n, err := b.RetireComponent("contextforge", "uninstall"); err != nil || n != 1 {
		t.Fatalf("retire: %d %v", n, err)
	}
	if _, err := b.DeliverComponent("contextforge", []string{"jwt-secret-key"}); err == nil {
		t.Fatal("retired credential delivered")
	}
}

func eventStrings(e audit.Event) []string {
	d, _ := e.Detail.(map[string]any)
	var out []string
	for _, v := range d {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case []string:
			out = append(out, x...)
		}
	}
	return out
}
