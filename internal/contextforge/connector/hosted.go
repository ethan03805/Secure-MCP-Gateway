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

	"github.com/modelcontextprotocol/go-sdk/mcp"

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
	if needsAPIKey(e) && (in.ProbeSecret == nil || in.ProbeSecret.Secret == "") {
		return refuse(packaging.Errf(ReasonProbeSecretRequired, "entry %s needs an API key: name the vault secret the probe sends (probe_secret); the Egress Broker inserts it on the probe's requests to the entry's host only (FR-22.9)", e.ID))
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
		c.probe(p, e, risk, actor, in.ProbeSecret)
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
func (c *Connector) probe(p *proposal, e *contextforge.Entry, risk, actor string, ps *ProbeSecret) {
	ctx, cancel := context.WithTimeout(context.Background(), c.o.BuildTimeout)
	defer cancel()
	dec, err := c.probeHosted(ctx, p, e, risk, actor, ps)
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

func (c *Connector) probeHosted(ctx context.Context, p *proposal, e *contextforge.Entry, risk, actor string, ps *ProbeSecret) (*Decision, error) {
	c.holdProbe()
	defer c.releaseProbe()
	if err := c.waitHealthy(ctx, actor); err != nil {
		return nil, err
	}
	// SR-3.5-2, FR-22.9: the probe reaches only the entry's host, through
	// an endpoint of its own, and holds no secret.
	target, release, err := c.probeEndpoint(ctx, p.ID, e.URL, ps)
	if err != nil {
		return nil, err
	}
	defer release()
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
	if needsAPIKey(e) {
		// FR-22.15: one secret slot, delivered only in mode S1 at the
		// package's endpoint for its host.
		m.Secrets = []packaging.SecretSlot{{Slot: "api_key", Purpose: "API key of the hosted server, inserted by the Egress Broker at the package's endpoint",
			Destination: net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(port)), Modes: []string{"S1"}}}
	}
	for _, n := range mapped {
		mt, err := manifestTool(byBackend[n.BackendName], n)
		if err != nil {
			return nil, err
		}
		m.Tools = append(m.Tools, mt)
	}
	lock := contextforge.ReleaseLock().ContextForge
	origin := &packaging.ContextForgeOrigin{CatalogSHA256: c.cat.SHA256, ContextForgeRelease: c.cat.Release, EntryID: e.ID, EntrySHA256: e.SHA256(),
		Class: contextforge.ClassHosted, URL: e.URL, Repo: e.Repo, InstanceDigest: c.instanceDigest(), ProbedAt: probedAt.Format(time.RFC3339)}
	origin.TLSPublicKeySHA256 = tlsKeyDigest(ctx, u)
	pv := packaging.Provenance{Builder: packaging.Builder{Tool: "smcpd contextforge connector", Version: c.o.Version},
		Probe:        packaging.ProbeEnvironment{Launcher: "contextforge " + lock.Version, Confined: c.o.Enforced, Network: c.probeNetwork(u), EnvNames: []string{}},
		ContextForge: origin}
	pkg, err := packaging.WriteHosted(filepath.Join(p.stage, "pkg"), m, pv, "smcpd contextforge connector", c.o.Version, c.o.Now())
	if err != nil {
		return nil, err
	}
	return hostedDecision(e, c.cat, pkg.Manifest, actor), nil
}

// needsAPIKey reports whether a catalog entry needs an API key (FR-22.15).
func needsAPIKey(e *contextforge.Entry) bool {
	return e.RequiresAPIKey || strings.Contains(strings.ToLower(e.AuthType), "api key")
}

// probeNetwork names the probe's network in the provenance (FR-22.11).
func (c *Connector) probeNetwork(u *url.URL) string {
	if c.o.EndpointFor != nil {
		return "test-endpoint"
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return "e18:" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
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
	for _, s := range m.Secrets {
		f.SecretSlots = append(f.SecretSlots, fmt.Sprintf("%s (%s at %s)", s.Slot, strings.Join(s.Modes, ", "), s.Destination))
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

// manifestTool builds a hosted manifest tool from the served definition.
// The definition goes through the same canonical form the Gateway gives a
// live tool list (packaging.CanonicalLive, after the MCP SDK has read it),
// so the drift check at launch compares like with like.
func manifestTool(t bundle.ServedTool, n contextforge.ToolName) (packaging.Tool, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return packaging.Tool{}, err
	}
	var st mcp.Tool
	if err := json.Unmarshal(raw, &st); err != nil {
		return packaging.Tool{}, packaging.Wrap(packaging.ReasonProbeFailed, "tool "+t.Name, err)
	}
	if st.InputSchema == nil {
		st.InputSchema = map[string]any{"type": "object"}
	}
	cts, err := packaging.CanonicalLive([]*mcp.Tool{&st})
	if err != nil {
		return packaging.Tool{}, err
	}
	ct := cts[0]
	mt := packaging.Tool{Name: n.Name, BackendName: n.BackendName, SideEffect: "external", SourceTrust: "untrusted"}
	mt.Title, _ = ct["title"].(string)
	mt.Description, _ = ct["description"].(string)
	mt.DescriptionSHA256 = packaging.SHA256Hex([]byte(mt.Description))
	for k, dst := range map[string]*json.RawMessage{"inputSchema": &mt.InputSchema, "outputSchema": &mt.OutputSchema, "annotations": &mt.Annotations} {
		if v, ok := ct[k]; ok {
			if *dst, err = json.Marshal(v); err != nil {
				return packaging.Tool{}, err
			}
		}
	}
	return mt, nil
}
