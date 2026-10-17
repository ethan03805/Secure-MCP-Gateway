package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const testConfig = `schema_version = 1
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA"
[policy]
file = "policy.json"
`

const testPolicy = `{"revision": "r1", "framework_profiles": {"dev": {"templates": ["ro"], "default_template": "ro"}},
 "templates": {"ro": {"rules": [{"id": "ro-t", "server": "t", "tools": ["echo"]}]}}}`

// install creates a state directory with keys and a journal, a
// configuration file and a policy file.
func install(t *testing.T, events ...audit.Event) (dir, state, cfg, pol string) {
	t.Helper()
	dir = t.TempDir()
	state = filepath.Join(dir, "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	priv, _ := keys.LoadEvidenceKey(state)
	j, err := audit.Open(filepath.Join(state, "journal"), priv, audit.Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := j.Commit(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(state, "log"), 0o700)
	_ = os.WriteFile(filepath.Join(state, "log", "smcpd.log"), []byte("{}\n"), 0o600)
	cfg = filepath.Join(dir, "smcp.toml")
	pol = filepath.Join(dir, "policy.json")
	_ = os.WriteFile(cfg, []byte(testConfig), 0o600)
	_ = os.WriteFile(pol, []byte(testPolicy), 0o644)
	return dir, state, cfg, pol
}

func fast(e Encryption) Encryption { e.WorkFactor = 10; return e }

func TestEncryptedArchives(t *testing.T) {
	// FR-17.6: a backup with a passphrase and one with a recipient, both
	// encrypted and both restorable; a backup with neither is refused.
	reqtest.Verifies(t, "FR-17.6")
	// FR-9.16 component list (Policy Store, configuration, journal, keys,
	// trust anchors, optional parts); scheduling and the vault and
	// registry directories of later elements are not covered.
	reqtest.Partial(t, "FR-9.16")
	dir, state, cfg, pol := install(t, audit.Event{Class: "admin", Origin: "E-24", Outcome: "x"})
	opt := filepath.Join(dir, "obs")
	_ = os.MkdirAll(opt, 0o700)
	_ = os.WriteFile(filepath.Join(opt, "day.parquet"), []byte("observations"), 0o600)
	spec := Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Optional: map[string]string{"observations": opt}, InstallationID: "inst-1"}

	out := filepath.Join(dir, "backups")
	if _, err := Create(out, spec); !errors.Is(err, ErrUnencrypted) {
		t.Fatalf("unencrypted backup: %v", err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Fatal("refused backup left files")
	}

	spec.Encryption = fast(Encryption{Passphrase: "correct horse battery"})
	res, err := Create(out, spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"configuration", "policy_store", "evidence_journal", "key_material", "trust_anchors", "optional:observations"} {
		if !res.Manifest.Has(c) {
			t.Errorf("manifest lacks %s: %v", c, res.Manifest.Components)
		}
	}
	for _, f := range res.Manifest.Files {
		if strings.HasPrefix(f.Path, "state/log/") {
			t.Errorf("diagnostic log archived: %s", f.Path)
		}
	}
	raw, _ := os.ReadFile(res.Path)
	if !strings.HasPrefix(string(raw), "age-encryption.org/v1") || strings.Contains(string(raw), "BEGIN EC PRIVATE KEY") || strings.Contains(string(raw), "revision") {
		t.Fatal("archive is not age ciphertext")
	}
	if ok, err := VerifyChecksum(res.Path); !ok || err != nil {
		t.Fatalf("checksum %v %v", ok, err)
	}
	if _, err := Extract(res.Path, filepath.Join(dir, "x1"), Decryption{Passphrase: "wrong"}); err == nil {
		t.Fatal("wrong passphrase decrypted")
	}
	m, err := Extract(res.Path, filepath.Join(dir, "x2"), Decryption{Passphrase: "correct horse battery"})
	if err != nil || m.InstallationID != "inst-1" {
		t.Fatalf("extract %+v %v", m, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "x2", "optional", "observations", "day.parquet")); string(b) != "observations" {
		t.Fatal("optional part not restored")
	}

	id, _ := age.GenerateX25519Identity()
	idFile := filepath.Join(dir, "id.txt")
	_ = os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600)
	spec.Encryption = Encryption{Recipients: []string{id.Recipient().String()}}
	spec.Now = func() time.Time { return time.Now().Add(time.Second) }
	res2, err := Create(out, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(res2.Path, filepath.Join(dir, "x3"), Decryption{IdentityFile: idFile}); err != nil {
		t.Fatalf("recipient archive: %v", err)
	}
	if _, err := Create(out, Spec{StateDir: state, Encryption: Encryption{Passphrase: "p", Recipients: []string{id.Recipient().String()}}}); err == nil {
		t.Fatal("passphrase and recipient together accepted")
	}
	idx, err := ReadIndex(out)
	if err != nil || len(idx) != 2 || idx[0].SHA256 != res.SHA256 || idx[1].Result != "ok" {
		t.Fatalf("index %+v %v", idx, err)
	}
	// A changed archive fails the recorded checksum.
	_ = os.WriteFile(res.Path, append(raw, 'x'), 0o600)
	if _, err := VerifyChecksum(res.Path); err == nil {
		t.Fatal("tampered archive passed the checksum")
	}
}

func TestRestoreVerifiesBeforeSwapping(t *testing.T) {
	// SR-7.8-1: isolated directory, archive checksum, journal chain and
	// signatures, policy validation and revocations from the restored and
	// the current journal before the swap. Policy revision signatures
	// (E-05) and the graph mirror rebuild (E-26) do not exist yet, and the
	// revocations are written for the credential elements to re-apply
	// rather than re-applied here (partial).
	reqtest.Partial(t, "SR-7.8-1")
	revoked := audit.Event{Class: "revocation", Origin: "E-22", Outcome: "revoked", ReasonCode: "CLIENT_REVOKED", PrincipalID: "p1"}
	dir, state, cfg, pol := install(t, revoked)
	res, err := Create(filepath.Join(dir, "backups"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"})})
	if err != nil {
		t.Fatal(err)
	}
	// After the backup: a later revocation in the current journal, and a
	// changed policy file.
	priv, _ := keys.LoadEvidenceKey(state)
	j, err := audit.Open(filepath.Join(state, "journal"), priv, audit.Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Commit(audit.Event{Class: "session", Origin: "E-04", Outcome: "revoked", ReasonCode: "SESSION_REVOKED", SessionID: "s9"})
	_ = j.Close()
	_ = os.WriteFile(pol, []byte(strings.Replace(testPolicy, `"r1"`, `"r2"`, 1)), 0o644)

	opts := RestoreOptions{Archive: res.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol}
	bad := opts
	bad.Decryption.Passphrase = "nope"
	if _, err := Restore(bad); err == nil {
		t.Fatal("wrong passphrase restored")
	}
	verify := opts
	verify.VerifyOnly = true
	rep, err := Restore(verify)
	if err != nil || rep.Applied || len(rep.Revocations) != 2 || !rep.ChecksumVerified {
		t.Fatalf("verify-only %+v %v", rep, err)
	}
	if b, _ := os.ReadFile(pol); !strings.Contains(string(b), `"r2"`) {
		t.Fatal("verify-only changed the policy")
	}
	rep, err = Restore(opts)
	if err != nil || !rep.Applied || rep.PolicyRevision != "r1" || rep.PreviousState == "" {
		t.Fatalf("restore %+v %v", rep, err)
	}
	if b, _ := os.ReadFile(pol); !strings.Contains(string(b), `"r1"`) {
		t.Fatal("policy not restored")
	}
	if _, err := os.Stat(filepath.Join(rep.PreviousState, "journal")); err != nil {
		t.Fatal("previous journal not kept")
	}
	b, err := os.ReadFile(filepath.Join(state, RevocationsFile))
	if err != nil || !strings.Contains(string(b), "CLIENT_REVOKED") || !strings.Contains(string(b), "SESSION_REVOKED") {
		t.Fatalf("revocations file %s %v", b, err)
	}
	root, _ := keys.LoadEvidenceTrustRoot(state)
	if _, err := audit.Verify(filepath.Join(state, "journal"), root); err != nil {
		t.Fatalf("restored journal: %v", err)
	}
	if es, _ := filepath.Glob(filepath.Join(dir, ".smcp-restore-*")); len(es) != 0 {
		t.Fatalf("isolated directory left behind: %v", es)
	}

	// A backup of a damaged journal is refused before anything changes.
	seg := filepath.Join(state, "journal", "segment-000001.jsonl")
	sb, _ := os.ReadFile(seg)
	_ = os.WriteFile(seg, []byte(strings.Replace(string(sb), "CLIENT_REVOKED", "CLIENT_REVOKEX", 1)), 0o600)
	res2, err := Create(filepath.Join(dir, "backups"), Spec{StateDir: state, ConfigPath: cfg, PolicyPath: pol, Encryption: fast(Encryption{Passphrase: "pw"}),
		Now: func() time.Time { return time.Now().Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(pol)
	if _, err := Restore(RestoreOptions{Archive: res2.Path, Decryption: Decryption{Passphrase: "pw"}, StateDir: state, ConfigPath: cfg, PolicyPath: pol}); err == nil || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("damaged journal restored: %v", err)
	}
	if after, _ := os.ReadFile(pol); string(after) != string(before) {
		t.Fatal("refused restore changed files")
	}
}
