package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
)

const catalogUsage = `usage: smcpctl catalog <command> [flags]

Browse the IBM ContextForge catalog and import local entries into the
Library. Without --config, list, show and import --dry-run read the catalog
of the ContextForge release pinned in this Gateway release, checked against
the release lock; an operator-supplied file needs --catalog and the --sha256
you confirm. With --config, they ask the running Gateway (control API) and
show each entry's import state. Nothing is installed or run from catalog
text.

  list                    every entry with its class (local, hosted or
                          unsupported) and the reason for unsupported ones
  show <id>               every field of one entry, its class, digest and
                          proposed artifact reference
  import --dry-run <id>   print the draft packaging recipe or hosted-manifest
                          draft and what the catalog does not provide
  import <id> --version V (--integrity I | --artifact-sha256 H)
         --argv ARG ... --license L [--accept SHA256 | --decline]
                          import a local entry through the running Gateway:
                          it fetches the pinned artifact, probes it, shows
                          the trust decision and, when you accept it, signs
                          the package with the catalog import key and
                          imports it disabled
  decide <proposal> (--accept SHA256 | --decline)
                          decide a waiting proposal (for example one
                          started from the console)
  status                  catalog source, release lock and the catalog
                          import key (an Administrator enrolls its public
                          key once with smcpctl trust add)

Flags:
  --config FILE                 ask the running Gateway (status, decide and
                                import without --dry-run always do)
  --catalog FILE                an operator-supplied catalog file (offline)
  --sha256 HEX                  the SHA-256 you confirm for --catalog
  --class CLASS                 list only local, hosted or unsupported entries
  --category C, --auth-type A, --query TEXT
                                filter the list (with --config)
  --json                        JSON output
  --version V                   exact artifact version (import)
  --artifact-sha256 HEX         artifact SHA-256 (import; PyPI wheel)
  --integrity sha512-...        npm registry integrity (import)
  --type npm|pypi, --package N  artifact type and package when the install
                                text does not name them (import)
  --argv ARG                    one launch argument, repeated in order (import)
  --license SPDX                a license of the artifact, repeatable (import)
  --risk-class C                moderate (default) or high (import)
  --side-effect C               default side-effect class of its tools (import)
  --accept SHA256               accept the decision whose text has this SHA-256
  --decline                     decline the decision
`

func catalogCmd(args []string, out io.Writer) error {
	subs := []string{"list", "show", "import", "decide", "status"}
	if len(args) < 1 || !slices.Contains(subs, args[0]) {
		fmt.Fprint(out, catalogUsage)
		return errors.New("catalog: subcommand list, show, import, decide or status required")
	}
	sub := args[0]
	fs := flag.NewFlagSet("catalog "+sub, flag.ContinueOnError)
	// Accepted and ignored: the commands were experimental in v1.2.
	fs.Bool("experimental-contextforge", false, "no longer needed")
	cfgPath := fs.String("config", "", "configuration file of the running Gateway")
	file := fs.String("catalog", "", "operator-supplied ContextForge mcp-catalog.yml")
	pin := fs.String("sha256", "", "SHA-256 the operator confirms for --catalog")
	release := fs.String("release", "", "ContextForge release of an operator-supplied catalog")
	version := fs.String("version", "", "exact artifact version (local entry)")
	artifactSHA := fs.String("artifact-sha256", "", "artifact SHA-256 (local entry)")
	integ := fs.String("integrity", "", "npm registry integrity (local entry)")
	typ := fs.String("type", "", "artifact type")
	pkg := fs.String("package", "", "artifact package name")
	var argv, licenses multiFlag
	fs.Var(&argv, "argv", "launch argument (repeat)")
	fs.Var(&licenses, "license", "license (repeat)")
	risk := fs.String("risk-class", "", "risk class")
	side := fs.String("side-effect", "", "default side-effect class")
	accept := fs.String("accept", "", "accept the decision with this SHA-256")
	decline := fs.Bool("decline", false, "decline the decision")
	class := fs.String("class", "", "list only this class")
	category := fs.String("category", "", "list only this category")
	auth := fs.String("auth-type", "", "list only this auth type")
	query := fs.String("query", "", "search text")
	asJSON := fs.Bool("json", false, "JSON output")
	dryRun := fs.Bool("dry-run", false, "print the mapped draft only")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	if *accept != "" && *decline {
		return errors.New("catalog: --accept and --decline exclude each other")
	}
	online := *cfgPath != "" || sub == "status" || sub == "decide" || (sub == "import" && !*dryRun)
	if online {
		if *file != "" {
			return errors.New("catalog: --catalog is for offline use; the running Gateway reads [contextforge] catalog_file")
		}
		if *cfgPath == "" {
			*cfgPath = "smcp.toml"
		}
		c, err := catalogClient(*cfgPath)
		if err != nil {
			return err
		}
		switch sub {
		case "status":
			return catalogStatusAPI(c, out, *asJSON)
		case "list":
			return catalogListAPI(c, out, url.Values{"class": {*class}, "category": {*category}, "auth_type": {*auth}, "q": {*query}}, *asJSON)
		case "show":
			if len(pos) != 1 {
				return errors.New("catalog show: exactly one entry ID is required")
			}
			return catalogShowAPI(c, out, pos[0])
		case "decide":
			if len(pos) != 1 || (*accept == "" && !*decline) {
				return errors.New("catalog decide: give one proposal ID and --accept SHA256 or --decline")
			}
			return catalogDecide(c, out, pos[0], *accept, *decline)
		}
		if len(pos) != 1 {
			return errors.New("catalog import: exactly one entry ID is required")
		}
		if *dryRun {
			return catalogShowAPI(c, out, pos[0])
		}
		body := map[string]any{"version": *version, "artifact_sha256": *artifactSHA, "integrity": *integ, "artifact_type": *typ,
			"package": *pkg, "argv": []string(argv), "licenses": []string(licenses), "risk_class": *risk, "side_effect": *side}
		return catalogImportAPI(c, out, pos[0], body, *accept, *decline)
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
