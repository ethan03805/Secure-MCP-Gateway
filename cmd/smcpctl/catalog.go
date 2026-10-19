package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
)

const catalogUsage = `usage: smcpctl catalog <list|show|import> [flags]

Reads the IBM ContextForge catalog (mcp-catalog.yml). By default this is the
catalog of the ContextForge release pinned in this Gateway release, checked
against the release lock. An operator-supplied file needs both --catalog and
the --sha256 you confirm. Nothing is fetched, installed or run.

  list                    every entry with its class (local, hosted or
                          unsupported) and the reason for unsupported ones
  show <id>               every field of one entry, its class, digest and
                          proposed artifact reference
  import --dry-run <id>   print the draft packaging recipe (local entry) or
                          draft hosted-package manifest (hosted entry), the
                          provenance the catalog provides and what is missing

Flags:
  --catalog FILE                an operator-supplied catalog file (at most 4 MiB)
  --sha256 HEX                  the SHA-256 you confirm for --catalog (required with it)
  --release TAG                 ContextForge release of an operator file (import)
  --version V                   exact artifact version of a local entry (import)
  --artifact-sha256 HEX         artifact SHA-256 of a local entry (import)
  --class CLASS                 list only local, hosted or unsupported entries (list)
  --json                        JSON output (list, show; import always prints JSON)
`

func catalogCmd(args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "list" && args[0] != "show" && args[0] != "import") {
		fmt.Fprint(out, catalogUsage)
		return errors.New("catalog: subcommand list, show or import required")
	}
	sub := args[0]
	fs := flag.NewFlagSet("catalog "+sub, flag.ContinueOnError)
	// Accepted and ignored: the commands were experimental in v1.2.
	fs.Bool("experimental-contextforge", false, "no longer needed")
	file := fs.String("catalog", "", "operator-supplied ContextForge mcp-catalog.yml")
	pin := fs.String("sha256", "", "SHA-256 the operator confirms for --catalog")
	release := fs.String("release", "", "ContextForge release of an operator-supplied catalog")
	version := fs.String("version", "", "exact artifact version (local entry)")
	artifactSHA := fs.String("artifact-sha256", "", "artifact SHA-256 (local entry)")
	class := fs.String("class", "", "list only this class")
	asJSON := fs.Bool("json", false, "JSON output")
	dryRun := fs.Bool("dry-run", false, "print the mapped draft only")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	cat, err := loadCatalog(*file, *pin)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		if len(pos) != 0 {
			return fmt.Errorf("catalog list: unexpected argument %q", pos[0])
		}
		return catalogList(out, cat, *class, *asJSON)
	case "show":
		if len(pos) != 1 {
			return errors.New("catalog show: exactly one entry ID is required")
		}
		return catalogShow(out, cat, pos[0], *asJSON)
	default:
		if !*dryRun {
			return errors.New("catalog import: only --dry-run is available from the command line in this build")
		}
		if len(pos) != 1 {
			return errors.New("catalog import: exactly one entry ID is required")
		}
		if *artifactSHA != "" && !isHex64(*artifactSHA) {
			return errors.New("catalog import: --artifact-sha256 must be 64 lowercase hex digits")
		}
		d, err := contextforge.DraftImport(cat, pos[0], contextforge.ImportOptions{Release: *release, Version: *version, ArtifactSHA256: *artifactSHA})
		if err != nil {
			return err
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
}

// loadCatalog reads the pinned catalog, or an operator file whose SHA-256
// the operator confirms (FR-22.1).
func loadCatalog(file, confirmed string) (*contextforge.Catalog, error) {
	if file == "" {
		if confirmed != "" {
			return nil, errors.New("catalog: --sha256 confirms an operator file; pass it with --catalog FILE")
		}
		return contextforge.PinnedCatalog()
	}
	raw, err := readCatalogFile(file)
	if err != nil {
		return nil, err
	}
	return contextforge.LoadConfirmed(raw, confirmed)
}

func readCatalogFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator-named input file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, contextforge.MaxCatalogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > contextforge.MaxCatalogBytes {
		return nil, fmt.Errorf("catalog: %s is larger than %d bytes", path, contextforge.MaxCatalogBytes)
	}
	return raw, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

type catalogRow struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Provider string   `json:"provider"`
	Category string   `json:"category"`
	Class    string   `json:"class"`
	AuthType string   `json:"auth_type"`
	URL      string   `json:"url,omitempty"`
	Install  string   `json:"install,omitempty"`
	Repo     string   `json:"repo,omitempty"`
	Reasons  []string `json:"unsupported_reasons,omitempty"`
	SHA256   string   `json:"entry_sha256"`
}

func catalogList(out io.Writer, cat *contextforge.Catalog, only string, asJSON bool) error {
	switch only {
	case "", contextforge.ClassLocal, contextforge.ClassHosted, contextforge.ClassUnsupported:
	default:
		return fmt.Errorf("catalog list: --class must be local, hosted or unsupported, not %q", only)
	}
	var rows []catalogRow
	for _, e := range cat.Entries {
		c, reasons := e.Classify()
		if only != "" && c != only {
			continue
		}
		rows = append(rows, catalogRow{ID: e.ID, Name: e.Name, Provider: e.Provider, Category: e.Category, Class: c,
			AuthType: e.AuthType, URL: e.URL, Install: e.Install, Repo: e.Repo, Reasons: reasons, SHA256: e.SHA256()})
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"catalog_sha256": cat.SHA256, "origin": cat.Origin, "release": cat.Release, "entries": rows})
	}
	fmt.Fprintf(out, "%s, %d of %d entries\n", catalogOrigin(cat), len(rows), len(cat.Entries))
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCLASS\tAUTH\tURL OR INSTALL\tNOTE")
	for _, r := range rows {
		ref := r.URL
		if r.Class == contextforge.ClassLocal {
			ref = r.Install
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", inert(r.ID, 40), r.Class, inert(r.AuthType, 20), inert(ref, 60), inert(strings.Join(r.Reasons, "; "), 80))
	}
	return tw.Flush()
}

// inert makes catalog text safe to print on a terminal: control and
// format characters (escape sequences, bidirectional overrides) become
// U+FFFD, and long values are cut.
func inert(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			b.WriteString("...")
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\t' {
			r = '\uFFFD'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func catalogOrigin(cat *contextforge.Catalog) string {
	if cat.Origin == contextforge.OriginPinned {
		return fmt.Sprintf("ContextForge %s catalog (pinned, sha256 %s)", cat.Release, cat.SHA256)
	}
	return fmt.Sprintf("operator catalog (sha256 %s, confirmed)", cat.SHA256)
}

// catalogShow prints one entry. Every catalog field is printed through
// inert; logo_url is shown as text and never loaded.
func catalogShow(out io.Writer, cat *contextforge.Catalog, id string, asJSON bool) error {
	e := cat.Entry(id)
	if e == nil {
		return fmt.Errorf("catalog show: %w: %q", contextforge.ErrUnknownEntry, id)
	}
	class, reasons := e.Classify()
	var prop *contextforge.Proposal
	if class == contextforge.ClassLocal {
		p := contextforge.ProposeArtifact(e.Install)
		prop = &p
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"catalog_sha256": cat.SHA256, "origin": cat.Origin, "release": cat.Release,
			"entry": e.Raw, "class": class, "unsupported_reasons": reasons,
			"entry_sha256": e.SHA256(), "artifact_proposal": prop,
		})
	}
	fmt.Fprintln(out, catalogOrigin(cat))
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	row := func(k, v string) { fmt.Fprintf(tw, "%s\t%s\n", k, inert(v, 200)) }
	row("id", e.ID)
	row("name", e.Name)
	row("provider", e.Provider)
	row("category", e.Category)
	row("class", class)
	if len(reasons) > 0 {
		row("unsupported because", strings.Join(reasons, "; "))
	}
	row("auth type", e.AuthType)
	row("url", e.URL)
	row("transport", e.Transport)
	row("repository", e.Repo)
	row("install (text only)", e.Install)
	row("tags", strings.Join(e.Tags, ", "))
	row("logo (not loaded)", e.LogoURL)
	row("entry sha256", e.SHA256())
	if prop != nil {
		ref := prop.Type + " " + prop.Name
		if prop.Version != "" {
			ref += "@" + prop.Version
		}
		row("proposed artifact", strings.TrimSpace(ref))
		if prop.Note != "" {
			row("note", prop.Note)
		}
	}
	row("description", e.Description)
	return tw.Flush()
}
