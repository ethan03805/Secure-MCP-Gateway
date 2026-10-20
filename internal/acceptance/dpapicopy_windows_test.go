//go:build windows

package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// The copy of a Gateway's state to a second host (FR-21.10, SR-2.13-4).
// The windows job of .github/workflows/ci.yml runs
// TestWindowsStateCopyExport on one runner with SMCP_DPAPI_EXPORT set to
// a directory, uploads that directory, and the windows-state-copy job
// runs TestWindowsStateCopyRefused on a second, fresh runner with
// SMCP_DPAPI_IMPORT set to the same path. DPAPI user-scope keys are
// derived from a master key of the account's profile on that host, so the
// second runner's account of the same name cannot decrypt them.

// exportRecord is what the exporting runner found, read by the importer.
type exportRecord struct {
	Host string `json:"host"`
	// Started is true when smcpd started healthy on the original host
	// with the protected keys and the dpapi vault, and stopped in order.
	Started bool `json:"started"`
	// Blobs are the private key files and the vault master key, each a
	// DPAPI blob, with their SHA-256.
	Blobs map[string]string `json:"blobs"`
	// Machine lists the private key files and the vault master key of the
	// machine-mode installation on the exporting runner (made by the
	// service under NT SERVICE\smcpd): each a DPAPI blob that the runner's
	// administrator account cannot decrypt.
	Machine map[string]string `json:"machine"`
}

const exportFile = "dpapi-export.json"

// TestWindowsStateCopyExport bootstraps an instance with a dpapi vault in
// $SMCP_DPAPI_EXPORT, starts it healthy (the normal start on the original
// host), stops it, checks that every private key file and the vault
// master key are DPAPI blobs, and records them for the importing runner.
// It also checks the machine-mode state that the machine-mode smoke test
// left in %ProgramData%\smcp-gateway, when present.
func TestWindowsStateCopyExport(t *testing.T) {
	dir := os.Getenv("SMCP_DPAPI_EXPORT")
	if dir == "" {
		t.Skip("set SMCP_DPAPI_EXPORT to export a state directory (CI windows job)")
	}
	reqtest.Partial(t, "FR-21.10", "SR-2.13-4")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	g := newGateway(t, options{dir: dir, extra: "\n[secrets]\nkey_source = \"dpapi\"\n"})
	g.start()
	g.stop()
	host, _ := os.Hostname()
	rec := exportRecord{Host: host, Started: true, Blobs: map[string]string{}, Machine: map[string]string{}}
	files := append(append([]string{}, keys.PrivateFiles...), filepath.Join("vault", secrets.DPAPIKeyFile))
	for _, name := range files {
		p := filepath.Join(g.state, name)
		b, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !winsec.IsProtectedBlob(b) {
			t.Fatalf("%s is not a DPAPI blob", name)
		}
		if _, err := winsec.Unprotect(b); err != nil {
			t.Fatalf("%s: this account cannot decrypt its own key: %v", name, err)
		}
		rec.Blobs[filepath.ToSlash(name)] = digest(b)
	}
	for _, must := range []string{keys.CAKeyFile, keys.EvidenceKeyFile, keys.AdminTokenFile, filepath.Join("vault", secrets.DPAPIKeyFile)} {
		if _, ok := rec.Blobs[filepath.ToSlash(must)]; !ok {
			t.Fatalf("%s missing from the state directory", must)
		}
	}
	// The machine-mode state, made by the service account (FR-21.10,
	// SR-2.13-4 in the machine mode): DPAPI blobs this administrator
	// account cannot decrypt.
	mstate := filepath.Join(os.Getenv("ProgramData"), "smcp-gateway", "state")
	if _, err := os.Stat(mstate); err == nil {
		for _, name := range files {
			b, err := os.ReadFile(filepath.Join(mstate, name))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if !winsec.IsProtectedBlob(b) {
				t.Fatalf("machine mode: %s is not a DPAPI blob", name)
			}
			if _, err := winsec.Unprotect(b); !errors.Is(err, winsec.ErrUnprotect) {
				t.Fatalf("machine mode: %s decrypted by the administrator account (%v); it must be bound to NT SERVICE\\smcpd", name, err)
			}
			rec.Machine[filepath.ToSlash(name)] = digest(b)
		}
		t.Logf("machine-mode state: %d DPAPI blobs bound to the service account", len(rec.Machine))
	}
	b, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, exportFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("exported %s from %s: %d DPAPI blobs", dir, host, len(rec.Blobs))
}

// TestWindowsStateCopyRefused performs the FR-21.10 verification on the
// second runner: the state directory copied from the first runner (the
// artifact of TestWindowsStateCopyExport, restored at the same path and
// protected as the Gateway protects it) is refused by smcpd with cause
// key_protection, no copied file is changed by the attempt, and the vault
// master key cannot be unlocked here (SR-2.13-4). Together with the
// export record (every private key file a DPAPI blob, a normal start on
// the original host, and the machine-mode keys bound to the service
// account) this is the whole verification statement of FR-21.10.
func TestWindowsStateCopyRefused(t *testing.T) {
	dir := os.Getenv("SMCP_DPAPI_IMPORT")
	if dir == "" {
		t.Skip("set SMCP_DPAPI_IMPORT to the copied state directory (CI windows-state-copy job)")
	}
	needBinaries(t)
	raw, err := os.ReadFile(filepath.Join(dir, exportFile))
	if err != nil {
		t.Fatal(err)
	}
	var rec exportRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if strings.EqualFold(host, rec.Host) {
		t.Fatalf("the importing runner %s is the exporting host; a second runner is needed", host)
	}
	if !rec.Started || len(rec.Blobs) == 0 {
		t.Fatalf("export record incomplete: %+v", rec)
	}
	// The artifact does not carry access control lists: give the copy the
	// owner-only DACL the Gateway gives its state, so that the start is
	// refused for the keys and not for the DACL (FR-21.5).
	if err := winsec.SecureOwnerOnly(dir); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	for name, sum := range rec.Blobs {
		b, err := os.ReadFile(filepath.Join(state, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if digest(b) != sum {
			t.Fatalf("%s changed in transit", name)
		}
		if _, err := winsec.Unprotect(b); !errors.Is(err, winsec.ErrUnprotect) {
			t.Fatalf("%s decrypted on a second host: %v", name, err)
		}
	}
	before := treeDigests(t, state)
	cmd := exec.Command(bin("smcpd"), "--config", filepath.Join(dir, "smcp.toml"))
	cmd.Dir = dir
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() { out, runErr = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("smcpd with a copied state directory did not stop:\n%s", out)
	}
	if runErr == nil {
		t.Fatalf("smcpd started with a state directory copied from %s:\n%s", rec.Host, out)
	}
	if !strings.Contains(string(out), "key_protection") {
		t.Fatalf("smcpd refused the copy without the cause key_protection:\n%s", out)
	}
	t.Logf("refused: %s", lastLine(string(out)))
	// The vault master key cannot be unlocked either (SR-2.13-4).
	if _, err := (secrets.DPAPI{Path: filepath.Join(state, "vault", secrets.DPAPIKeyFile)}).Load(); !errors.Is(err, secrets.ErrLocked) {
		t.Fatalf("vault master key on a second host: %v", err)
	}
	after := treeDigests(t, state)
	for name, sum := range before {
		if strings.HasPrefix(name, "journal/") || strings.HasPrefix(name, "log/") {
			continue // a refused start may append its own records
		}
		if after[name] != sum {
			t.Fatalf("%s was changed by the refused start", name)
		}
	}
	for name := range rec.Blobs {
		if _, ok := after[name]; !ok {
			t.Fatalf("%s was removed by the refused start", name)
		}
	}
	if len(rec.Machine) > 0 {
		t.Logf("machine-mode keys of %s: %d DPAPI blobs bound to NT SERVICE\\smcpd", rec.Host, len(rec.Machine))
		reqtest.Verifies(t, "FR-21.10")
	} else {
		reqtest.Partial(t, "FR-21.10") // the machine-mode keys were not checked
	}
	reqtest.Partial(t, "SR-2.13-4")
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func treeDigests(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = digest(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
