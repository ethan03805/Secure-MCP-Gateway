package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// RestoreOptions configure Restore. The Gateway must not be running.
type RestoreOptions struct {
	Archive    string
	Decryption Decryption
	// Target paths: the state directory, configuration file and policy
	// file of the installation being restored.
	StateDir   string
	ConfigPath string
	PolicyPath string
	// VerifyOnly decrypts and verifies into the isolated directory and
	// removes it without changing the installation.
	VerifyOnly bool
	Now        func() time.Time
}

// Revocation is one revocation found in a journal. Restore re-applies
// every one found in the restored and the current journal by writing them
// to state/revocations.json, which the elements that issue credentials
// read at startup.
type Revocation struct {
	EventID    string `json:"event_id"`
	Time       string `json:"time"`
	Class      string `json:"class"`
	ReasonCode string `json:"reason_code"`
	SessionID  string `json:"session_id,omitempty"`
	Principal  string `json:"principal_id,omitempty"`
	Detail     any    `json:"detail,omitempty"`
}

// RevocationsFile holds the re-applied revocations under the state
// directory.
const RevocationsFile = "revocations.json"

// RestoreReport describes a restore.
type RestoreReport struct {
	Archive          string       `json:"archive"`
	ChecksumVerified bool         `json:"checksum_verified"`
	Manifest         Manifest     `json:"manifest"`
	JournalSegments  int          `json:"journal_segments"`
	JournalEvents    int          `json:"journal_events"`
	JournalKeys      int          `json:"journal_keys"`
	PolicyRevision   string       `json:"policy_revision"`
	Revocations      []Revocation `json:"revocations"`
	GraphMirror      string       `json:"graph_mirror"`
	Isolated         string       `json:"isolated_dir"`
	PreviousState    string       `json:"previous_state,omitempty"`
	Applied          bool         `json:"applied"`
}

// Restore decrypts the archive into an isolated directory next to the
// state directory, verifies the archive checksum (when the .sha256 file is
// present), every entry against the manifest, the journal chain,
// signatures and anchor, the policy file and the configuration, collects
// the revocations recorded in the restored and the current journal, and
// only then swaps the restored state, configuration and policy into place
// (SR-7.8-1). The previous state directory is kept as
// <state>.pre-restore-<time>, so evidence written after the backup is not
// lost.
func Restore(o RestoreOptions) (RestoreReport, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	rep := RestoreReport{Archive: o.Archive, GraphMirror: "not configured; nothing to rebuild"}
	ok, err := VerifyChecksum(o.Archive)
	if err != nil {
		return rep, err
	}
	rep.ChecksumVerified = ok
	stamp := o.Now().UTC().Format("20060102T150405Z")
	parent := filepath.Dir(filepath.Clean(o.StateDir))
	iso, err := os.MkdirTemp(parent, ".smcp-restore-"+stamp+"-")
	if err != nil {
		return rep, err
	}
	rep.Isolated = iso
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(iso)
		}
	}()
	if rep.Manifest, err = Extract(o.Archive, iso, o.Decryption); err != nil {
		return rep, err
	}
	rstate := filepath.Join(iso, "state")
	root, err := keys.LoadEvidenceTrustRoot(rstate)
	if err != nil {
		return rep, fmt.Errorf("restored evidence key: %w", err)
	}
	jr, err := audit.Verify(filepath.Join(rstate, "journal"), root)
	if err != nil {
		return rep, fmt.Errorf("restored journal does not verify: %w", err)
	}
	rep.JournalSegments, rep.JournalEvents, rep.JournalKeys = jr.Segments, jr.Events, len(jr.Keys)
	cfgFile, polFile := single(iso, "config"), single(iso, "policy")
	if cfgFile == "" || polFile == "" {
		return rep, errors.New("archive lacks the configuration or the policy file")
	}
	raw, err := os.ReadFile(cfgFile)
	if err != nil {
		return rep, err
	}
	if _, err := config.Parse(raw); err != nil {
		return rep, fmt.Errorf("restored configuration: %w", err)
	}
	snap, err := policy.Load(polFile)
	if err != nil {
		return rep, fmt.Errorf("restored policy: %w", err)
	}
	rep.PolicyRevision = snap.Revision
	revs, err := revocations(filepath.Join(rstate, "journal"))
	if err != nil {
		return rep, err
	}
	if cur := filepath.Join(o.StateDir, "journal"); exists(cur) {
		more, err := revocations(cur)
		if err != nil {
			return rep, fmt.Errorf("current journal: %w", err)
		}
		revs = mergeRevocations(revs, more)
	}
	rep.Revocations = revs
	if err := writeRevocations(rstate, revs); err != nil {
		return rep, err
	}
	if o.VerifyOnly {
		return rep, nil
	}

	// Swap. The previous state stays next to the restored one.
	if exists(o.StateDir) {
		rep.PreviousState = o.StateDir + ".pre-restore-" + stamp
		if err := os.Rename(o.StateDir, rep.PreviousState); err != nil {
			return rep, err
		}
	}
	if err := os.Rename(rstate, o.StateDir); err != nil {
		if rep.PreviousState != "" {
			_ = os.Rename(rep.PreviousState, o.StateDir)
		}
		return rep, err
	}
	for _, f := range []struct{ src, dst string }{{cfgFile, o.ConfigPath}, {polFile, o.PolicyPath}} {
		if f.dst == "" {
			continue
		}
		if exists(f.dst) {
			if err := copyFile(f.dst, f.dst+".pre-restore-"+stamp, 0o600); err != nil {
				return rep, err
			}
		}
		if err := copyFile(f.src, f.dst, 0o600); err != nil {
			return rep, err
		}
	}
	rep.Applied = true
	return rep, nil
}

// single returns the one file in iso/<dir>, or "".
func single(iso, dir string) string {
	es, err := os.ReadDir(filepath.Join(iso, dir))
	if err != nil || len(es) != 1 || es[0].IsDir() {
		return ""
	}
	return filepath.Join(iso, dir, es[0].Name())
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(dst, b, mode)
}

// isRevocation reports whether an event revokes a credential, a session
// or a server. Elements record revocations with a reason code ending in
// _REVOKED or with class "revocation".
func isRevocation(ev audit.Event) bool {
	return ev.Class == "revocation" || strings.HasSuffix(ev.ReasonCode, "_REVOKED") || ev.Outcome == "revoked"
}

func revocations(journalDir string) ([]Revocation, error) {
	evs, err := audit.ReadEvents(journalDir)
	if err != nil {
		return nil, err
	}
	var out []Revocation
	for _, ev := range evs {
		if isRevocation(ev) {
			out = append(out, Revocation{EventID: ev.EventID, Time: ev.Time, Class: ev.Class, ReasonCode: ev.ReasonCode, SessionID: ev.SessionID, Principal: ev.PrincipalID, Detail: ev.Detail})
		}
	}
	return out, nil
}

func mergeRevocations(a, b []Revocation) []Revocation {
	seen := map[string]bool{}
	var out []Revocation
	for _, r := range append(a, b...) {
		if !seen[r.EventID] {
			seen[r.EventID] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Time < out[k].Time })
	return out
}

func writeRevocations(stateDir string, revs []Revocation) error {
	if revs == nil {
		revs = []Revocation{}
	}
	b, err := jsonIndent(revs)
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(filepath.Join(stateDir, RevocationsFile), b, 0o600)
}
