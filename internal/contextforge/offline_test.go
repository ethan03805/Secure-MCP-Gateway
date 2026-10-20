package contextforge

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// offlineChild runs in the network namespace of TestCatalogOfflineImage:
// it reports whether the network is reachable and the result of each
// catalog load, one line each.
func offlineChild(opFile, opSHA string) {
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err == nil {
		c.Close()
		fmt.Println("network reachable")
	} else {
		fmt.Println("network unreachable")
	}
	report := func(name string, c *Catalog, err error) {
		if err != nil {
			fmt.Println(name, packaging.ReasonOf(err))
			return
		}
		fmt.Println(name, "loaded", len(c.Entries))
	}
	cat, err := PinnedCatalog()
	report("pinned", cat, err)
	changed := bytes.Clone(pinnedCatalogYAML)
	changed[len(changed)/2] ^= 0x20
	cat, err = LoadPinned(changed, ReleaseLock())
	report("pinned_one_byte_changed", cat, err)
	raw, _ := os.ReadFile(opFile)
	cat, err = LoadConfirmed(raw, opSHA)
	report("operator_confirmed", cat, err)
	cat, err = LoadConfirmed(raw, "")
	report("operator_unconfirmed", cat, err)
	cat, err = LoadConfirmed(raw, strings.Repeat("0", 64))
	report("operator_other_digest", cat, err)
}

// TestCatalogOfflineImage is FR-22.1 with outbound network access blocked
// (the contextforge job: SMCP_CONTEXTFORGE_IMAGE=1, Linux with
// unprivileged user namespaces): the test binary runs again in a new
// network namespace, where nothing but an unconfigured loopback exists,
// and loads the pinned catalog (loaded), the pinned file with one byte
// changed (CATALOG_DIGEST_MISMATCH), an operator file with its confirmed
// SHA-256 (loaded), and the same file without a confirmed digest and with
// another digest (CATALOG_DIGEST_MISMATCH). The catalog code imports no
// network client (TestCatalogCodeHasNoNetworkOrExec), so no connection can
// be attempted; the namespace makes any attempt fail.
func TestCatalogOfflineImage(t *testing.T) {
	if os.Getenv("SMCP_CF_OFFLINE_CHILD") == "1" {
		offlineChild(os.Getenv("SMCP_CF_OFFLINE_FILE"), os.Getenv("SMCP_CF_OFFLINE_SHA"))
		return
	}
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" || runtime.GOOS != "linux" {
		t.Skip("runs in the contextforge job (Linux, unprivileged user namespaces)")
	}
	if err := exec.Command("unshare", "--user", "--map-root-user", "--net", "true").Run(); err != nil {
		t.Skipf("no unprivileged network namespace: %v", err)
	}
	op := []byte("catalog_servers:\n  - id: op-entry\n    name: Operator entry\n    provider: Example\n    auth_type: Open\n    url: https://op.example.com/mcp\n")
	file := filepath.Join(t.TempDir(), "operator.yml")
	if err := os.WriteFile(file, op, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--net", os.Args[0], "-test.run=^TestCatalogOfflineImage$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SMCP_CF_OFFLINE_CHILD=1", "SMCP_CF_OFFLINE_FILE="+file, "SMCP_CF_OFFLINE_SHA="+packaging.SHA256Hex(op))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	t.Logf("in a network namespace without network:\n%s", out)
	got := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if name, rest, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			got[name] = rest
		}
	}
	want := map[string]string{
		"network":                 "unreachable",
		"pinned":                  "loaded 135",
		"pinned_one_byte_changed": ReasonCatalogDigestMismatch,
		"operator_confirmed":      "loaded 1",
		"operator_unconfirmed":    ReasonCatalogDigestMismatch,
		"operator_other_digest":   ReasonCatalogDigestMismatch,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if !t.Failed() {
		reqtest.Verifies(t, "FR-22.1")
	}
}
