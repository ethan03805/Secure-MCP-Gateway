// Package connector is the Gateway side of the ContextForge Connector
// (E-36, SRS FR-22, planned for v1.3.0): it serves the ContextForge catalog
// on the control API, imports local catalog entries through packaging
// (FR-22.6) after an operator trust decision (FR-22.12), signs them with the
// Gateway's catalog import key, hands them to the Library (E-13, E-14) as
// verified-disabled revisions (FR-22.13) and records the evidence of each
// attempt (FR-22.14). Hosted entries need the bundled ContextForge instance
// and are refused with CONTEXTFORGE_DISABLED while it is off (FR-22.22).
package connector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

// Files under <state>/contextforge.
const (
	dirName     = "contextforge"
	keyFile     = "import-signing.key"
	pubFile     = "import-signing.pub"
	importsFile = "imports.json"
	stagingDir  = "staging"
)

// ProposalTTL is how long a built proposal waits for the operator's
// decision before it is abandoned.
const ProposalTTL = time.Hour

// Event classes of the Connector (FR-22.14).
const (
	ClassImport        = "catalog_import"
	ClassTrustDecision = "catalog_trust_decision"
)

// Importer is the part of the Library the Connector uses.
type Importer interface {
	Dir() string
	Import(dir string, o library.ImportOptions) (*library.Receipt, error)
	Revisions() []library.Revision
	SetState(id, rev, state, reason, actor string) (library.Revision, string, error)
}

// Options configure a Connector.
type Options struct {
	Config   *config.Config
	Library  Importer
	Recorder audit.Recorder
	// Launcher runs the probe of a local import (nil: unconfined
	// subprocess, as `smcpctl package build` without --sandbox).
	Launcher pipeline.Launcher
	// Confined is true when servers run in the sandbox ([runtime] sandbox
	// = "podman"). The probe of a local import must then be sandboxed too
	// (SR-3.5-1); until that probe is wired, local imports are refused
	// with SANDBOXED_PROBE_UNAVAILABLE.
	Confined bool
	// Broker holds the bundled instance's credentials (nil without
	// [secrets]; the instance then cannot run).
	Broker *secrets.Broker
	// EndpointFor maps a hosted URL to the URL the bundled instance
	// registers for it (the entry's E-18 endpoint). Nil: the hosted URL
	// itself.
	EndpointFor func(hostedURL string) (string, error)
	// SSRFAllowed are the networks the bundled instance may reach (the
	// E-18 endpoint addresses, FR-22.27).
	SSRFAllowed []string
	// Suspend suspends an enabled revision for cause (drift, a broken
	// scope); smcpd passes library.Runtime.SuspendRevision.
	Suspend func(id, rev string, cause error) error
	// Enforced is true in the Enforced profile; elsewhere the bundled
	// instance is reported contextforge_unconfined (FR-22.25).
	Enforced bool
	Interp   packaging.Interpreters
	Version  string
	Now      func() time.Time
	Log      *slog.Logger
	// BuildTimeout bounds one local build (default 15 minutes).
	BuildTimeout time.Duration
}

// Connector is the ContextForge Connector.
type Connector struct {
	o       Options
	dir     string
	key     minisign.PrivateKey
	pub     []byte
	cat     *contextforge.Catalog
	catErr  error
	fetcher *packaging.Fetcher

	mu        sync.Mutex
	proposals map[string]*proposal
	imports   *importsDoc

	// The bundled instance (instance.go); nil unless [contextforge]
	// bundled is true and it could be prepared (instErr says why not).
	inst     *bundle.Instance
	instErr  error
	verifier *bundle.Verifier
	verified *bundle.Verification
	platform string
	instMu   sync.Mutex

	// Registered hosted packages (dispatch.go), by virtual server ID.
	hostedMu     sync.Mutex
	hosted       map[string]*hostedPkg
	cleanedAt    time.Time
	reconcileReq chan struct{}

	// Demand for the instance (demand.go, FR-22.23).
	demandMu     sync.Mutex
	probes       int
	operatorHold bool
	idleSince    time.Time

	wg sync.WaitGroup
}

// New opens the Connector: it loads the catalog (the pinned one, or the
// configured operator file with its confirmed digest), creates the
// catalog import key on first use and removes proposals left over from a
// previous run. A catalog that fails its checks is reported by Status and
// the catalog routes; it does not stop the Gateway.
func New(o Options) (*Connector, error) {
	if o.Config == nil || o.Library == nil {
		return nil, errors.New("contextforge connector: config and library required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.BuildTimeout <= 0 {
		o.BuildTimeout = 15 * time.Minute
	}
	c := &Connector{o: o, dir: filepath.Join(o.Config.State.Dir, dirName), proposals: map[string]*proposal{},
		hosted: map[string]*hostedPkg{}, reconcileReq: make(chan struct{}, 1),
		fetcher: &packaging.Fetcher{NPMRegistry: o.Config.ContextForge.NPMRegistry, PyPIIndex: o.Config.ContextForge.PyPIIndex}}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(filepath.Join(c.dir, stagingDir))
	if err := c.loadKey(); err != nil {
		return nil, err
	}
	var err error
	if c.imports, err = loadImports(filepath.Join(c.dir, importsFile)); err != nil {
		return nil, err
	}
	if o.Config.ContextForge.Bundled {
		c.setupInstance()
	}
	c.cat, c.catErr = loadCatalog(o.Config.ContextForge)
	if c.catErr != nil {
		o.Log.Warn("contextforge catalog refused", "reason", packaging.ReasonOf(c.catErr), "error", c.catErr)
	}
	return c, nil
}

func loadCatalog(cf config.ContextForge) (*contextforge.Catalog, error) {
	if cf.CatalogFile == "" {
		return contextforge.PinnedCatalog()
	}
	f, err := os.Open(cf.CatalogFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, contextforge.MaxCatalogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > contextforge.MaxCatalogBytes {
		return nil, packaging.Errf(contextforge.ReasonCatalogInvalid, "catalog: %s is larger than %d bytes", cf.CatalogFile, contextforge.MaxCatalogBytes)
	}
	return contextforge.LoadConfirmed(raw, cf.CatalogSHA256)
}

// loadKey reads or creates the catalog import key. It is an unencrypted
// minisign key protected by file mode, like the policy-signing key; it
// signs only packages whose trust decision an operator accepted, and it
// admits nothing until an Administrator enrolls its public key as a trust
// anchor (FR-14.8, FR-7.10).
func (c *Connector) loadKey() error {
	kp, pp := filepath.Join(c.dir, keyFile), filepath.Join(c.dir, pubFile)
	raw, err := os.ReadFile(kp)
	if errors.Is(err, os.ErrNotExist) {
		sec, pub, _, gerr := packaging.GenerateKey("")
		if gerr != nil {
			return gerr
		}
		if err := os.WriteFile(kp, sec, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(pp, pub, 0o644); err != nil { // #nosec G306 -- a public key
			return err
		}
		raw = sec
	} else if err != nil {
		return err
	}
	if c.key, err = packaging.ParseSecretKey(raw, ""); err != nil {
		return fmt.Errorf("catalog import key %s: %w", kp, err)
	}
	pub := c.key.Public().(minisign.PublicKey)
	text, err := pub.MarshalText()
	if err != nil {
		return err
	}
	c.pub = append(text, '\n')
	return nil
}

// KeyID is the minisign key ID of the catalog import key.
func (c *Connector) KeyID() string { return packaging.KeyID(c.key.ID()) }

// keyEnrolled reports whether the import key is an enrolled, unexpired
// trust anchor, and the risk classes it may admit.
func (c *Connector) keyEnrolled() (bool, []string) {
	a, err := packaging.LoadAnchors(c.o.Config.State.Dir)
	if err != nil {
		return false, nil
	}
	for _, an := range a.Anchors {
		if an.KeyID == c.KeyID() && c.o.Now().Before(an.Expires) {
			return true, an.Classes
		}
	}
	return false, nil
}

// SetRecorder sets the evidence recorder once the journal is open (smcpd
// creates the Connector before app.Start so that hosted packages resolve
// at the first launch).
func (c *Connector) SetRecorder(rec audit.Recorder) { c.o.Recorder = rec }

// Catalog returns the loaded catalog or the reason it was refused.
func (c *Connector) Catalog() (*contextforge.Catalog, error) { return c.cat, c.catErr }

// Close stops the bundled instance and waits for running builds.
func (c *Connector) Close() {
	c.closeInstance()
	c.wg.Wait()
}

// Start runs the proposal janitor until ctx ends.
func (c *Connector) Start(ctx context.Context) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		d := time.NewTicker(demandTick)
		defer d.Stop()
		rc := time.NewTicker(ReconcileInterval)
		defer rc.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.expire()
			case <-d.C:
				c.onDemand(ctx)
			case <-rc.C:
				c.reconcile(ctx)
			case <-c.reconcileReq:
				c.reconcile(ctx)
			}
		}
	}()
}

// expire abandons proposals older than ProposalTTL.
func (c *Connector) expire() {
	now := c.o.Now()
	c.mu.Lock()
	var gone []*proposal
	for id, p := range c.proposals {
		if p.State != stateBuilding && now.Sub(p.created) > ProposalTTL {
			delete(c.proposals, id)
			gone = append(gone, p)
		}
	}
	c.mu.Unlock()
	for _, p := range gone {
		_ = os.RemoveAll(p.stage)
		if p.State == stateReady {
			_ = c.importEvent(p, "abandoned", ReasonProposalExpired, "no decision within "+ProposalTTL.String(), "", "")
		}
	}
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// entryState is an entry's import state for G-15 and `smcpctl catalog`.
type entryState struct {
	State     string   `json:"import_state"` // not_imported, imported, changed
	Revisions []string `json:"revisions,omitempty"`
}

// stateOf is FR-22.16: an entry is "changed" when the catalog's digest of
// it differs from the digest of the latest import.
func (c *Connector) stateOf(e *contextforge.Entry) entryState {
	c.mu.Lock()
	defer c.mu.Unlock()
	recs := c.imports.forEntry(e.ID)
	if len(recs) == 0 {
		return entryState{State: "not_imported"}
	}
	st := entryState{State: "imported"}
	for _, r := range recs {
		st.Revisions = append(st.Revisions, r.ServerID+"@"+r.Revision)
	}
	sort.Strings(st.Revisions)
	if recs[len(recs)-1].EntrySHA256 != e.SHA256() {
		st.State = "changed"
	}
	return st
}

// event commits one Connector evidence event.
func (c *Connector) event(class, outcome, reason, serverRev string, detail map[string]any) error {
	if c.o.Recorder == nil {
		return nil
	}
	return c.o.Recorder.Commit(audit.Event{Class: class, Origin: "E-36", Outcome: outcome, ReasonCode: reason,
		ServerRevision: serverRev, PolicyStatus: "not_evaluated", Detail: detail})
}

// importEvent records the catalog_import event of one attempt (FR-22.14).
func (c *Connector) importEvent(p *proposal, outcome, reason, msg, serverID, revision string) error {
	d := map[string]any{"entry_id": p.EntryID, "entry_sha256": p.EntrySHA256, "class": p.Class,
		"catalog_sha256": p.CatalogSHA256, "actor": p.Actor, "outcome": outcome, "proposal_id": p.ID}
	if msg != "" {
		d["reason"] = msg
	}
	rev := ""
	if serverID != "" {
		d["server_id"], d["revision"] = serverID, revision
		rev = serverID + "@" + revision
	}
	return c.event(ClassImport, outcome, reason, rev, d)
}

func lower(s string) string { return strings.ToLower(s) }
