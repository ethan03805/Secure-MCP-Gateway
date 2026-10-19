package contextforge

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Proposal is the artifact reference proposed from an install string. The
// string is only read as text (FR-22.7): it is split on spaces, never
// passed to a shell, and refused when it carries shell syntax.
type Proposal struct {
	Type    string `json:"type,omitempty"`    // npm or pypi
	Name    string `json:"name,omitempty"`    // package name
	Version string `json:"version,omitempty"` // only when the install string pins an exact version
	Command string `json:"command,omitempty"` // console script named by the install string, if any
	// Note explains a refused or partial proposal.
	Note string `json:"note,omitempty"`
}

var (
	shellSyntax = regexp.MustCompile("[;&|<>$`\\\\'\"(){}\\[\\]*?!~#\\n\\r]")
	npmName     = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	pypiName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	exactVer    = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*([-+._]?[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)
)

// ProposeArtifact reads an install string such as "npx -y @scope/pkg@1.2.3",
// "uvx pkg", "uvx --from pkg cmd" or a bare console-script name.
func ProposeArtifact(install string) Proposal {
	if shellSyntax.MatchString(install) {
		return Proposal{Note: "install string contains shell syntax; nothing proposed (shown verbatim only)"}
	}
	f := strings.Fields(install)
	if len(f) == 0 {
		return Proposal{Note: "empty install string"}
	}
	switch f[0] {
	case "npx":
		var rest []string
		for _, a := range f[1:] {
			if a == "-y" || a == "--yes" {
				continue
			}
			rest = append(rest, a)
		}
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return Proposal{Type: "npm", Note: "npx without a package argument the importer understands"}
		}
		name, ver := splitNPM(rest[0])
		p := Proposal{Type: "npm", Name: name}
		if !npmName.MatchString(name) {
			return Proposal{Type: "npm", Note: fmt.Sprintf("%q is not an npm package name", name)}
		}
		switch {
		case ver == "":
			p.Note = "no version in the install string; the operator must pin one (FR-14.2)"
		case !exactVer.MatchString(ver) || isDistTag(ver):
			p.Note = fmt.Sprintf("version %q is not exact; the operator must pin one (FR-14.2)", ver)
		default:
			p.Version = ver
		}
		if len(rest) > 1 {
			p.Note = strings.TrimSpace(p.Note + "; extra arguments " + strings.Join(rest[1:], " ") + " are not carried into the launch argv")
		}
		return p
	case "uvx":
		args := f[1:]
		var from string
		if len(args) >= 2 && args[0] == "--from" {
			from, args = args[1], args[2:]
		}
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			return Proposal{Type: "pypi", Note: "uvx without a command the importer understands"}
		}
		pkg := args[0]
		if from != "" {
			pkg = from
		}
		name, ver, _ := strings.Cut(pkg, "==")
		if !pypiName.MatchString(name) {
			return Proposal{Type: "pypi", Note: fmt.Sprintf("%q is not a PyPI project name", name)}
		}
		p := Proposal{Type: "pypi", Name: name, Command: args[0]}
		if ver != "" && exactVer.MatchString(ver) {
			p.Version = ver
		} else {
			p.Note = "no exact version in the install string; the operator must pin one (FR-14.2)"
		}
		return p
	default:
		if len(f) == 1 && pypiName.MatchString(f[0]) {
			return Proposal{Command: f[0], Note: "a bare command name: the registry and package are not stated; the operator must name the artifact type, package and version"}
		}
		return Proposal{Note: fmt.Sprintf("install runner %q is not understood", f[0])}
	}
}

func splitNPM(s string) (name, ver string) {
	at := strings.LastIndex(s, "@")
	if at <= 0 { // no version, or only the scope's leading @
		return s, ""
	}
	return s[:at], s[at+1:]
}

func isDistTag(v string) bool {
	switch strings.ToLower(v) {
	case "latest", "next", "stable", "beta", "alpha", "canary", "rc", "dev", "edge", "nightly", "main", "master", "head":
		return true
	}
	return false
}

// ImportOptions are the operator's inputs to a dry-run import.
type ImportOptions struct {
	// Release is the ContextForge release the catalog file comes from,
	// for example "v1.0.11".
	Release string
	// Version and ArtifactSHA256 pin a local entry's artifact (FR-22.6).
	Version        string
	ArtifactSHA256 string
}

// Provenance is what the catalog lets the Gateway record (FR-22.11, the
// part available before any fetch or probe).
type Provenance struct {
	CatalogSHA256       string `json:"catalog_sha256"`
	ContextForgeRelease string `json:"contextforge_release,omitempty"`
	EntryID             string `json:"catalog_entry_id"`
	EntrySHA256         string `json:"catalog_entry_sha256"`
	URL                 string `json:"url,omitempty"`
	Repo                string `json:"repo,omitempty"`
	Install             string `json:"install,omitempty"`
}

// Upstream is the manifest_version 2 member of a hosted package
// (FR-22.10): the hosted endpoint, the catalog entry it came from and the
// ContextForge gateway name and slug fixed at the probe.
type Upstream struct {
	Kind        string `json:"kind"`
	URL         string `json:"url"`
	Transport   string `json:"transport"`
	EntryID     string `json:"catalog_entry_id"`
	EntrySHA256 string `json:"catalog_entry_sha256"`
	GatewayName string `json:"gateway_name"`
	GatewaySlug string `json:"gateway_slug"`
}

// HostedDraft is a draft hosted-package manifest: every member that can be
// derived without the probe. Tools come from the quarantine probe (FR-22.9).
type HostedDraft struct {
	ManifestVersion int                    `json:"manifest_version"`
	Server          packaging.ServerInfo   `json:"server"`
	Upstream        Upstream               `json:"upstream"`
	RiskClass       string                 `json:"risk_class"`
	ToolDefaults    packaging.ToolClass    `json:"tool_defaults"`
	Tools           []packaging.Tool       `json:"tools"`
	Capabilities    packaging.Capabilities `json:"capabilities"`
	Secrets         []packaging.SecretSlot `json:"secrets,omitempty"`
}

// Draft is the dry-run result printed by `smcpctl catalog import --dry-run`.
type Draft struct {
	EntryID  string   `json:"entry_id"`
	Name     string   `json:"name,omitempty"`
	Provider string   `json:"provider,omitempty"`
	AuthType string   `json:"auth_type,omitempty"`
	Class    string   `json:"class"`
	Reasons  []string `json:"unsupported_reasons,omitempty"`

	Proposal *Proposal         `json:"artifact_proposal,omitempty"`
	Recipe   *packaging.Recipe `json:"recipe,omitempty"`
	Hosted   *HostedDraft      `json:"hosted_manifest,omitempty"`

	Provenance Provenance `json:"provenance"`
	// ProvenanceGaps names what FR-22.11 and the packaging checks need
	// that the catalog does not provide.
	ProvenanceGaps []string `json:"provenance_gaps"`
	// OperatorMustSupply lists inputs missing before a real import.
	OperatorMustSupply []string `json:"operator_must_supply,omitempty"`
	NextSteps          []string `json:"next_steps,omitempty"`
}

// ErrUnknownEntry is returned for an entry id not in the catalog.
var ErrUnknownEntry = errors.New("no such catalog entry")

// DraftImport maps one entry to a draft without touching the network.
func DraftImport(c *Catalog, id string, o ImportOptions) (*Draft, error) {
	e := c.Entry(id)
	if e == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownEntry, id)
	}
	class, reasons := e.Classify()
	d := &Draft{
		EntryID: e.ID, Name: e.Name, Provider: e.Provider, AuthType: e.AuthType,
		Class: class, Reasons: reasons,
		Provenance: Provenance{
			CatalogSHA256: c.SHA256, ContextForgeRelease: o.Release,
			EntryID: e.ID, EntrySHA256: e.SHA256(),
			URL: e.URL, Repo: e.Repo, Install: e.Install,
		},
	}
	if o.Release == "" && c.Origin == OriginPinned {
		d.Provenance.ContextForgeRelease = c.Release
	}
	if d.Provenance.ContextForgeRelease == "" {
		d.OperatorMustSupply = append(d.OperatorMustSupply, "the ContextForge release the catalog file belongs to (--release); FR-22.1 reads it from the release lock")
	}
	switch class {
	case ClassLocal:
		draftLocal(d, e, o)
	case ClassHosted:
		draftHosted(d, e)
	default:
		d.ProvenanceGaps = []string{"entry is unsupported; nothing to import"}
	}
	return d, nil
}

func serverID(id string) string {
	id = strings.ToLower(id)
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	if s == "" {
		s = "contextforge-entry"
	}
	return s
}

func alias(id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
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

func httpsOrEmpty(s string) string {
	if u, err := url.Parse(s); err == nil && u.Scheme == "https" && u.Host != "" {
		return s
	}
	return ""
}

func description(e *Entry) string {
	s := e.Description
	if r := []rune(s); len(r) > 2000 {
		s = string(r[:2000])
	}
	return s
}

func draftLocal(d *Draft, e *Entry, o ImportOptions) {
	p := ProposeArtifact(e.Install)
	d.Proposal = &p
	ver := p.Version
	if o.Version != "" {
		ver = o.Version
	}
	r := &packaging.Recipe{
		RecipeVersion: 1,
		Server: packaging.ServerInfo{
			ID: serverID(e.ID), Alias: alias(e.ID), Publisher: e.Provider,
			Description: description(e), Homepage: httpsOrEmpty(e.Repo),
		},
		Artifact:      packaging.ArtifactRef{Type: p.Type, Name: p.Name, Version: ver, SHA256: o.ArtifactSHA256},
		RiskClass:     "moderate",
		InstanceScope: []string{"shared"},
		Tools:         packaging.RecipeTools{Default: packaging.ToolClass{SideEffect: "external", SourceTrust: "untrusted"}},
		Capabilities:  packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{}, Egress: []packaging.EgressRule{}},
		Launch:        packaging.Launch{Argv: []string{}},
		Licenses:      []string{},
		OperatorNote:  "Drafted from ContextForge catalog entry " + e.ID + " (catalog sha256 " + d.Provenance.CatalogSHA256 + "). Review every field before building.",
	}
	switch p.Type {
	case "npm":
		r.Launch.Runtime = "node"
	case "pypi":
		r.Launch.Runtime = "python"
	}
	if e.RequiresAPIKey || strings.Contains(strings.ToLower(e.AuthType), "api key") {
		r.Secrets = []packaging.SecretSlot{{Slot: "api_key", Purpose: "API key named by the catalog entry", Modes: []string{"S3"}}}
	}
	d.Recipe = r
	must := []string{}
	if p.Type == "" {
		must = append(must, "the artifact type (npm, pypi, oci or binary) and package name: the install string does not state them")
	}
	if ver == "" {
		must = append(must, "an exact artifact version (--version); catalog install strings are unpinned or use dist-tags")
	}
	if o.ArtifactSHA256 == "" {
		must = append(must, "the artifact SHA-256 (--artifact-sha256), compared with the registry by smcpctl package build (FR-14.2)")
	}
	must = append(must,
		"launch.argv: the entry point inside the artifact (the catalog names only a runner command)",
		"licenses: the catalog has no license field",
		"tool classification (side_effect, source_trust, risk_class) after the probe lists the tools",
		"the dependency lock (npm lock file or pip requirements with hashes)")
	d.OperatorMustSupply = append(d.OperatorMustSupply, must...)
	d.ProvenanceGaps = []string{
		"the catalog states no version, digest, license, signer or source commit for any entry",
		"repo is a repository home page, not a tag or commit bound to the artifact",
		"the install string is a runner command (npx, uvx) and is never executed (FR-22.7)",
	}
	d.NextSteps = []string{
		"complete the recipe, then: smcpctl package build --recipe <recipe.json> --out <dir>",
		"smcpctl package sign, smcpctl package import (the package starts disabled, FR-22.13)",
	}
}

func draftHosted(d *Draft, e *Entry) {
	u, _ := url.Parse(e.URL)
	transport := strings.ToUpper(e.Transport)
	if transport == "" {
		transport = "STREAMABLEHTTP"
		if strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/sse") {
			transport = "SSE"
		}
	}
	port := 443
	if p := u.Port(); p != "" {
		_, _ = fmt.Sscanf(p, "%d", &port)
	}
	h := &HostedDraft{
		ManifestVersion: 2,
		Server: packaging.ServerInfo{
			ID: serverID(e.ID), Alias: alias(e.ID), Publisher: e.Provider,
			Description: description(e), Homepage: httpsOrEmpty(e.DocumentationURL),
		},
		Upstream: Upstream{
			Kind: "contextforge-hosted", URL: e.URL, Transport: transport,
			EntryID: e.ID, EntrySHA256: d.Provenance.EntrySHA256,
			GatewayName: GatewayName(e.ID), GatewaySlug: GatewayName(e.ID),
		},
		RiskClass:    "moderate",
		ToolDefaults: packaging.ToolClass{SideEffect: "external", SourceTrust: "untrusted"},
		Tools:        []packaging.Tool{},
		Capabilities: packaging.Capabilities{
			Filesystem: []packaging.FilesystemSlot{},
			Egress:     []packaging.EgressRule{{Host: u.Hostname(), Ports: []int{port}, Methods: []string{"GET", "POST", "DELETE"}}},
		},
	}
	if h.Server.Homepage == "" {
		h.Server.Homepage = httpsOrEmpty(e.Repo)
	}
	if e.RequiresAPIKey || strings.Contains(strings.ToLower(e.AuthType), "api key") {
		h.Secrets = []packaging.SecretSlot{{Slot: "api_key", Purpose: "API key named by the catalog entry", Destination: u.Hostname(), Modes: []string{"S1"}}}
	}
	d.Hosted = h
	d.OperatorMustSupply = append(d.OperatorMustSupply,
		"the quarantine probe (FR-22.9) for tools, schemas, description digests and tools_list_sha256",
		"a trust decision acknowledging that the hosted server's code cannot be inspected (FR-22.12)")
	if len(h.Secrets) > 0 {
		d.OperatorMustSupply = append(d.OperatorMustSupply, "a probe secret bound for S1 delivery to "+u.Hostname()+" (FR-22.15)")
	}
	d.ProvenanceGaps = []string{
		"a hosted entry has no artifact: no version, digest, license or source can be verified, only the endpoint",
		"serverInfo name and version and the TLS public key digest are only known after the probe (FR-22.11)",
		"ContextForge serves tools as <gateway_slug>-<name>; each tool's manifest name is derived from that backend name at the probe (FR-22.10)",
	}
	d.NextSteps = []string{"the probe, the trust decision, signing and import run through the bundled ContextForge instance ([contextforge] bundled = true, FR-22.9, FR-22.22)"}
}
