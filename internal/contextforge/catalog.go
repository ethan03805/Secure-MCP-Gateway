// Package contextforge is the EXPERIMENTAL ContextForge catalog reader of
// the ContextForge spike (docs/contextforge-spike.md). It parses an IBM
// ContextForge mcp-catalog.yml under the bounds proposed for FR-22.2,
// classifies entries as proposed for FR-22.3 and maps one entry to a draft
// packaging recipe (local entries) or a draft hosted-package manifest
// (hosted entries) for `smcpctl catalog import --dry-run`. Nothing here
// fetches, installs, runs or signs anything, and none of it is part of a
// release requirement yet (FR-22 is planned for v1.3.0).
package contextforge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Bounds proposed by FR-22.2.
const (
	MaxCatalogBytes = 4 << 20
	MaxEntries      = 2000
	MaxStringChars  = 4096
	// maxDepth bounds nesting; catalog entries are at most four levels
	// deep (catalog_servers / entry / oauth / scopes).
	maxDepth = 16
)

// Classes of a catalog entry (FR-22.3).
const (
	ClassLocal       = "local"
	ClassHosted      = "hosted"
	ClassUnsupported = "unsupported"
)

// Catalog is a parsed catalog file.
type Catalog struct {
	// SHA256 is the hex SHA-256 of the file bytes.
	SHA256  string
	Entries []*Entry
}

// Entry is one catalog_servers element. Known fields are decoded; Raw is
// the whole element as a generic value, the input of the canonical digest.
type Entry struct {
	ID               string
	Name             string
	Category         string
	URL              string
	AuthType         string
	Provider         string
	Description      string
	RequiresAPIKey   bool
	Tags             []string
	Transport        string
	Repo             string
	Install          string
	DocumentationURL string
	LogoURL          string

	Raw map[string]any
}

// ParseCatalog parses raw as a ContextForge catalog. It refuses the whole
// file when it is larger than MaxCatalogBytes, is not exactly one YAML
// document, uses an anchor, alias, explicit tag or merge key, nests deeper
// than maxDepth, has more than MaxEntries entries, has a string longer than
// MaxStringChars, or has an entry without a unique string id.
func ParseCatalog(raw []byte) (*Catalog, error) {
	if len(raw) > MaxCatalogBytes {
		return nil, fmt.Errorf("catalog: %d bytes, more than %d", len(raw), MaxCatalogBytes)
	}
	sum := sha256.Sum256(raw)
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("catalog: more than one YAML document")
	}
	if err := checkNode(&doc, 0); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("catalog: top level is not a mapping")
	}
	var servers *yaml.Node
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "catalog_servers" {
			servers = top.Content[i+1]
		}
	}
	if servers == nil || servers.Kind != yaml.SequenceNode {
		return nil, errors.New("catalog: catalog_servers is missing or not a list")
	}
	if len(servers.Content) > MaxEntries {
		return nil, fmt.Errorf("catalog: %d entries, more than %d", len(servers.Content), MaxEntries)
	}
	c := &Catalog{SHA256: hex.EncodeToString(sum[:])}
	seen := map[string]bool{}
	for i, n := range servers.Content {
		if n.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("catalog: entry %d is not a mapping", i)
		}
		v, err := toValue(n)
		if err != nil {
			return nil, fmt.Errorf("catalog: entry %d: %w", i, err)
		}
		m := v.(map[string]any)
		e := &Entry{Raw: m}
		e.ID = str(m, "id")
		if e.ID == "" {
			return nil, fmt.Errorf("catalog: entry %d has no id", i)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("catalog: duplicate entry id %q", e.ID)
		}
		seen[e.ID] = true
		e.Name, e.Category, e.URL = str(m, "name"), str(m, "category"), str(m, "url")
		e.AuthType, e.Provider, e.Description = str(m, "auth_type"), str(m, "provider"), str(m, "description")
		e.Transport, e.Repo, e.Install = str(m, "transport"), str(m, "repo"), str(m, "install")
		e.DocumentationURL, e.LogoURL = str(m, "documentation_url"), str(m, "logo_url")
		e.RequiresAPIKey, _ = m["requires_api_key"].(bool)
		if tags, ok := m["tags"].([]any); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					e.Tags = append(e.Tags, s)
				}
			}
		}
		c.Entries = append(c.Entries, e)
	}
	return c, nil
}

// Entry returns the entry with the given id, or nil.
func (c *Catalog) Entry(id string) *Entry {
	for _, e := range c.Entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// checkNode enforces the structural rules on the parsed tree before any
// value is built from it.
func checkNode(n *yaml.Node, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("nesting deeper than %d (line %d)", maxDepth, n.Line)
	}
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("alias at line %d is not allowed", n.Line)
	}
	if n.Anchor != "" {
		return fmt.Errorf("anchor %q at line %d is not allowed", n.Anchor, n.Line)
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("explicit tag %q at line %d is not allowed", n.Tag, n.Line)
	}
	if n.Kind == yaml.ScalarNode && len([]rune(n.Value)) > MaxStringChars {
		return fmt.Errorf("string at line %d is longer than %d characters", n.Line, MaxStringChars)
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Tag == "!!merge" || (k.Kind == yaml.ScalarNode && k.Value == "<<" && k.Style == 0) {
				return fmt.Errorf("merge key at line %d is not allowed", k.Line)
			}
			if k.Kind != yaml.ScalarNode {
				return fmt.Errorf("non-scalar mapping key at line %d", k.Line)
			}
		}
	}
	for _, c := range n.Content {
		if err := checkNode(c, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// toValue converts a checked node to plain Go values (map[string]any,
// []any, string, bool, int64, float64, nil). Mapping keys must be unique.
func toValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if _, dup := m[k]; dup {
				return nil, fmt.Errorf("duplicate key %q at line %d", k, n.Content[i].Line)
			}
			v, err := toValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, nil
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := toValue(c)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		return s, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!null":
			return nil, nil
		case "!!bool":
			b, err := strconv.ParseBool(strings.ToLower(n.Value))
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n.Line, err)
			}
			return b, nil
		case "!!int":
			i, err := strconv.ParseInt(n.Value, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n.Line, err)
			}
			return i, nil
		case "!!float":
			f, err := strconv.ParseFloat(n.Value, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n.Line, err)
			}
			return f, nil
		case "!!str", "":
			return n.Value, nil
		default:
			return nil, fmt.Errorf("line %d: scalar type %s is not allowed", n.Line, n.Tag)
		}
	default:
		return nil, fmt.Errorf("line %d: unexpected node", n.Line)
	}
}

// CanonicalJSON is the entry's canonical JSON form: object keys sorted,
// no insignificant white space, no HTML escaping. Its SHA-256 is the entry
// digest that FR-22.11 and FR-22.16 compare.
func (e *Entry) CanonicalJSON() []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(e.Raw) // map keys are sorted by encoding/json
	return bytes.TrimRight(b.Bytes(), "\n")
}

// SHA256 is the hex SHA-256 of CanonicalJSON.
func (e *Entry) SHA256() string {
	s := sha256.Sum256(e.CanonicalJSON())
	return hex.EncodeToString(s[:])
}

// Classify returns the entry's class and, for an unsupported entry, the
// reasons (FR-22.3 as proposed): local when it names a repo and an install
// command; hosted when its url is https and it names no install command;
// unsupported otherwise, and always when its auth type needs OAuth 2.1
// (no Gateway-held OAuth client yet) or a plain-http URL points off the
// host.
func (e *Entry) Classify() (string, []string) {
	var reasons []string
	if strings.Contains(strings.ToLower(e.AuthType), "oauth2.1") {
		reasons = append(reasons, "auth_type "+strconv.Quote(e.AuthType)+" needs OAuth 2.1, which the Gateway cannot hold for a hosted server yet")
	}
	u, uerr := url.Parse(e.URL)
	if e.URL == "" || uerr != nil || u.Host == "" {
		reasons = append(reasons, "missing or invalid url")
	} else if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		reasons = append(reasons, "plain http url to a non-loopback host")
	}
	switch {
	case e.Repo != "" && e.Install != "":
		if len(reasons) > 0 && !onlyURLReasons(reasons) {
			return ClassUnsupported, reasons
		}
		return ClassLocal, nil
	case e.Install == "" && uerr == nil && u.Scheme == "https" && u.Host != "":
		if len(reasons) > 0 {
			return ClassUnsupported, reasons
		}
		return ClassHosted, nil
	}
	if e.Install == "" && e.Repo != "" {
		reasons = append(reasons, "names a repo but no install command")
	}
	if e.Install != "" && e.Repo == "" {
		reasons = append(reasons, "names an install command but no repo")
	}
	if e.Install == "" && e.Repo == "" && (uerr != nil || u.Scheme != "https") {
		reasons = append(reasons, "neither an install command nor an https url")
	}
	sort.Strings(reasons)
	return ClassUnsupported, reasons
}

// onlyURLReasons reports whether every reason concerns the url, which a
// local entry does not use (its server runs as a package, FR-22.8).
func onlyURLReasons(r []string) bool {
	for _, s := range r {
		if !strings.Contains(s, "url") {
			return false
		}
	}
	return true
}

func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
