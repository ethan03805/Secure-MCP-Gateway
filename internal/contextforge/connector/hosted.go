package connector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ProposeHosted starts the import of a hosted entry (FR-22.9, FR-22.10):
// with the bundled instance running, it registers the entry as a probe
// package (team, non-admin user, gateway, virtual server, scoped token),
// reads the served tool list with the package's own token, removes the
// probe objects, maps the served names to manifest names and writes the
// manifest_version 2 package, then presents the trust decision.
func (c *Connector) ProposeHosted(id string, in LocalImport, actor string) (proposal, error) {
	e, err := c.entry(id)
	if err != nil {
		return proposal{}, err
	}
	class, _ := e.Classify()
	now := c.o.Now()
	p := &proposal{ID: newID(), EntryID: e.ID, EntrySHA256: e.SHA256(), CatalogSHA256: c.cat.SHA256, Class: class,
		Actor: actor, State: stateBuilding, Created: now.UTC().Format(time.RFC3339), created: now}
	refuse := func(err error) (proposal, error) {
		p.State, p.ReasonCode, p.Error = stateFailed, packaging.ReasonOf(err), err.Error()
		if eerr := c.importEvent(p, "refused", p.ReasonCode, err.Error(), "", ""); eerr != nil {
			return proposal{}, eerr
		}
		return p.view(), err
	}
	if class != contextforge.ClassHosted {
		return refuse(packaging.Errf(ReasonEntryUnsupported, "entry %s is %s, not hosted", e.ID, class))
	}
	if !c.o.Config.ContextForge.Bundled {
		return refuse(packaging.Errf(contextforge.ReasonContextForgeDisabled,
			"hosted entry %s needs the bundled ContextForge instance, and [contextforge] bundled is false", e.ID))
	}
	if c.instErr != nil {
		return refuse(c.instErr)
	}
	if e.RequiresAPIKey || strings.Contains(strings.ToLower(e.AuthType), "api key") {
		return refuse(packaging.Errf(ReasonHostedNotAvailable, "entry %s needs an API key; the probe secret (S1 delivery at the E-18 endpoint, FR-22.9) is not built yet", e.ID))
	}
	risk := in.RiskClass
	if risk == "" {
		risk = "moderate"
	}
	if risk != "moderate" && risk != "high" {
		return refuse(packaging.Errf(packaging.ReasonManifestSchema, "a hosted package's risk class is moderate or high, not %q (SR-3-6)", risk))
	}
	p.stage = filepath.Join(c.dir, stagingDir, p.ID)
	if err := os.MkdirAll(p.stage, 0o700); err != nil {
		return refuse(err)
	}
	c.mu.Lock()
	c.proposals[p.ID] = p
	c.mu.Unlock()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.probe(p, e, risk, actor)
	}()
	return p.view(), nil
}

// waitHealthy starts the instance when it is stopped and waits for it.
func (c *Connector) waitHealthy(ctx context.Context, actor string) error {
	if st := c.inst.Status().State; st == bundle.StateStopped {
		if err := c.StartInstance(ctx, actor); err != nil {
			return err
		}
	}
	for !c.inst.Healthy() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("the bundled ContextForge instance did not become healthy: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil
}

func (c *Connector) admin() *bundle.Admin {
	return &bundle.Admin{Base: c.inst.BaseURL(), AdminToken: func() (string, error) { return c.inst.AdminToken(5 * time.Minute) }}
}

// probe runs the hosted-entry probe of a proposal.
func (c *Connector) probe(p *proposal, e *contextforge.Entry, risk, actor string) {
	ctx, cancel := context.WithTimeout(context.Background(), c.o.BuildTimeout)
	defer cancel()
	dec, err := c.probeHosted(ctx, p, e, risk, actor)
	c.mu.Lock()
	if err != nil {
		p.State, p.ReasonCode, p.Error = stateFailed, packaging.ReasonOf(err), err.Error()
		if p.ReasonCode == "" {
			p.ReasonCode = packaging.ReasonProbeFailed
		}
	} else {
		p.State, p.Decision = stateReady, dec
		p.Expires = p.created.Add(ProposalTTL).UTC().Format(time.RFC3339)
	}
	c.mu.Unlock()
	if err != nil {
		_ = os.RemoveAll(p.stage)
		if eerr := c.importEvent(p, "refused", p.ReasonCode, err.Error(), "", ""); eerr != nil {
			c.o.Log.Error("contextforge import evidence", "error", eerr)
		}
	}
}

func (c *Connector) probeHosted(ctx context.Context, p *proposal, e *contextforge.Entry, risk, actor string) (*Decision, error) {
	c.holdProbe()
	defer c.releaseProbe()
	if err := c.waitHealthy(ctx, actor); err != nil {
		return nil, err
	}
	target, err := c.endpointFor(e.URL)
	if err != nil {
		return nil, err
	}
	slug := contextforge.GatewayName(e.ID)
	pw, err := bundle.NewCredential()
	if err != nil {
		return nil, err
	}
	a := c.admin()
	probedAt := c.o.Now().UTC()
	prov, err := a.Provision(ctx, bundle.PackageSpec{Slug: slug, URL: target, Transport: transportOf(e)}, pw)
	if prov == nil {
		prov = &bundle.Provisioned{Slug: slug, UserEmail: bundle.UserEmail(slug)}
	}
	// The probe objects are removed whatever happened; the enabled
	// package is registered again under the same gateway name.
	defer func() { _ = a.Deprovision(context.WithoutCancel(ctx), prov) }()
	if err != nil {
		return nil, packaging.Wrap(packaging.ReasonProbeFailed, "registering the hosted entry in the bundled instance", err)
	}
	served, err := a.ServedTools(ctx, prov)
	if err != nil {
		return nil, packaging.Wrap(packaging.ReasonProbeFailed, "reading the served tool list", err)
	}
	if len(served) == 0 {
		return nil, packaging.Errf(packaging.ReasonProbeFailed, "the hosted server lists no tools")
	}
	names := make([]string, 0, len(served))
	for _, t := range served {
		names = append(names, t.Name)
	}
	mapped, err := contextforge.MapToolNames(slug, names)
	if err != nil {
		return nil, err
	}
	byBackend := map[string]bundle.ServedTool{}
	for _, t := range served {
		byBackend[t.Name] = t
	}
	u, _ := url.Parse(e.URL)
	port := 443
	if s := u.Port(); s != "" {
		port, _ = strconv.Atoi(s)
	}
	m := &packaging.Manifest{
		Server:    packaging.ServerInfo{ID: hostedServerID(e.ID), Revision: fmt.Sprintf("1+cf.%d", c.nextImport(e.ID)), Alias: hostedAlias(e.ID), Publisher: firstNonEmpty(e.Provider, "unknown"), Description: clip(e.Description, 2000)},
		Upstream:  &packaging.Upstream{Kind: "contextforge-hosted", URL: e.URL, Transport: transportOf(e), EntryID: e.ID, EntrySHA256: e.SHA256(), GatewayName: slug, GatewaySlug: slug},
		Era:       "2025-11-25",
		RiskClass: risk,
		Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{},
			Egress: []packaging.EgressRule{{Host: strings.ToLower(u.Hostname()), Ports: []int{port}, Methods: []string{"GET", "POST", "DELETE"}}}},
		Packaging: packaging.PackagingInfo{OperatorNote: "Hosted package of ContextForge catalog entry " + e.ID + "."},
	}
	for _, n := range mapped {
		t := byBackend[n.BackendName]
		in := t.InputSchema
		if len(in) == 0 || string(in) == "null" {
			in = json.RawMessage(`{"type":"object"}`)
		}
		mt := packaging.Tool{Name: n.Name, BackendName: n.BackendName, Title: t.Title, Description: clip(t.Description, 8192), InputSchema: in,
			SideEffect: "external", SourceTrust: "untrusted"}
		mt.DescriptionSHA256 = packaging.SHA256Hex([]byte(mt.Description))
		if len(t.OutputSchema) > 0 && string(t.OutputSchema) != "null" {
			mt.OutputSchema = t.OutputSchema
		}
		if len(t.Annotations) > 0 && string(t.Annotations) != "null" && string(t.Annotations) != "{}" {
			mt.Annotations = t.Annotations
		}
		m.Tools = append(m.Tools, mt)
	}
	lock := contextforge.ReleaseLock().ContextForge
	origin := &packaging.ContextForgeOrigin{CatalogSHA256: c.cat.SHA256, ContextForgeRelease: c.cat.Release, EntryID: e.ID, EntrySHA256: e.SHA256(),
		Class: contextforge.ClassHosted, URL: e.URL, Repo: e.Repo, InstanceDigest: lock.Image.Platforms[c.platform], ProbedAt: probedAt.Format(time.RFC3339)}
	origin.TLSPublicKeySHA256 = tlsKeyDigest(ctx, u)
	pv := packaging.Provenance{Builder: packaging.Builder{Tool: "smcpd contextforge connector", Version: c.o.Version},
		Probe:        packaging.ProbeEnvironment{Launcher: "contextforge " + lock.Version, Confined: c.o.Enforced, Network: "host", EnvNames: []string{}},
		ContextForge: origin}
	pkg, err := packaging.WriteHosted(filepath.Join(p.stage, "pkg"), m, pv, "smcpd contextforge connector", c.o.Version, c.o.Now())
	if err != nil {
		return nil, err
	}
	return hostedDecision(e, c.cat, pkg.Manifest, actor), nil
}

// endpointFor is the URL the bundled instance registers for a hosted
// entry: the entry's E-18 endpoint when Options.EndpointFor is set (tests
// and, later, the Egress Broker), the hosted URL itself otherwise.
func (c *Connector) endpointFor(u string) (string, error) {
	if c.o.EndpointFor != nil {
		return c.o.EndpointFor(u)
	}
	return u, nil
}

func transportOf(e *contextforge.Entry) string {
	t := strings.ToUpper(e.Transport)
	if t == "SSE" || (t == "" && strings.HasSuffix(strings.TrimRight(e.URL, "/"), "/sse")) {
		return "SSE"
	}
	return "STREAMABLEHTTP"
}

// tlsKeyDigest is the SHA-256 of the hosted server's TLS public key
// (SubjectPublicKeyInfo) seen by a handshake from the Gateway, or "" when
// it cannot be read (FR-22.11).
func tlsKeyDigest(ctx context.Context, u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	d := &tls.Dialer{Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, NetDialer: &net.Dialer{Timeout: 10 * time.Second}}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// hostedDecision is the trust decision of a hosted entry (FR-22.12,
// SR-3-6): it states that the server's code cannot be inspected.
func hostedDecision(e *contextforge.Entry, cat *contextforge.Catalog, m *packaging.Manifest, actor string) *Decision {
	f := Presented{Class: contextforge.ClassHosted, Provider: e.Provider, URL: e.URL, AuthType: e.AuthType, RiskClass: m.HighestRisk(),
		Tools: []string{}, SideEffects: []string{}, Egress: []string{}, SecretSlots: []string{}, NotInspected: true}
	sides := map[string]bool{}
	for _, t := range m.Tools {
		f.Tools = append(f.Tools, fmt.Sprintf("%s (served as %s; %s, %s)", t.Name, t.BackendName, t.SideEffect, t.SourceTrust))
		sides[t.SideEffect] = true
	}
	for s := range sides {
		f.SideEffects = append(f.SideEffects, s)
	}
	sort.Strings(f.SideEffects)
	for _, g := range m.Capabilities.Egress {
		f.Egress = append(f.Egress, fmt.Sprintf("%s ports %v", g.Host, g.Ports))
	}
	none := func(v []string) string {
		if len(v) == 0 {
			return "none"
		}
		return strings.Join(v, "; ")
	}
	release := cat.Release
	if release == "" {
		release = "operator-supplied catalog"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Import ContextForge catalog entry %s (%s) as %s@%s.\n", e.ID, e.Name, m.Server.ID, m.Server.Revision)
	fmt.Fprintf(&b, "Class: hosted\nProvider: %s\nURL: %s\nAuth type: %s\n", f.Provider, f.URL, f.AuthType)
	fmt.Fprintf(&b, "Risk class: %s\nTools (%d): %s\nSide-effect classes: %s\nEgress destinations: %s\nSecret slots: %s\n",
		f.RiskClass, len(m.Tools), none(f.Tools), none(f.SideEffects), none(f.Egress), none(f.SecretSlots))
	fmt.Fprintf(&b, "Catalog: sha256 %s (%s); entry sha256 %s.\n", cat.SHA256, release, e.SHA256())
	fmt.Fprintf(&b, "The code of this hosted server cannot be inspected, and its operator sees every argument sent to it. "+
		"It is reached only through the bundled ContextForge instance, which every hosted package shares. Every tool is marked untrusted. "+
		"Accepting signs the package with this Gateway's catalog import key as %s's decision. ContextForge and IBM have not reviewed this server. "+
		"The package is imported disabled and no policy grant changes.\n", actor)
	text := b.String()
	sum := sha256.Sum256([]byte(text))
	return &Decision{Text: text, SHA256: hex.EncodeToString(sum[:]), Fields: f}
}

func hostedServerID(entryID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(entryID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if s == "" {
		s = "contextforge-entry"
	}
	return s
}

func hostedAlias(entryID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(entryID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() == 16 {
			break
		}
	}
	if b.Len() == 0 {
		return "cf"
	}
	return b.String()
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func firstNonEmpty(v ...string) string {
	if i := slices.IndexFunc(v, func(s string) bool { return s != "" }); i >= 0 {
		return v[i]
	}
	return ""
}

// ProposeStarterSet offers the starter set of the release lock as one
// import (FR-22.17): one hosted proposal per entry, each with its own
// probe, trust decision and signature, none enabled. It is refused while
// the bundled instance is off.
func (c *Connector) ProposeStarterSet(actor string) ([]proposal, error) {
	if !c.o.Config.ContextForge.Bundled {
		return nil, packaging.Errf(contextforge.ReasonContextForgeDisabled, "the starter set is offered only while [contextforge] bundled is true")
	}
	if c.catErr != nil {
		return nil, c.catErr
	}
	var out []proposal
	for _, id := range contextforge.ReleaseLock().ContextForge.StarterSet {
		p, err := c.ProposeHosted(id, LocalImport{}, actor)
		if err != nil && p.ID == "" {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}
