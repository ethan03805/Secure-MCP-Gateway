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

const catalogUsage = `usage: smcpctl catalog <list|import> --experimental-contextforge --catalog FILE [flags]

EXPERIMENTAL (ContextForge spike, docs/contextforge-spike.md). Reads an IBM
ContextForge mcp-catalog.yml from a local file only; nothing is fetched,
installed, run, signed or imported.

  list                    every entry with its class (local, hosted or
                          unsupported) and the reason for unsupported ones
  import --dry-run <id>   print the draft packaging recipe (local entry) or
                          draft hosted-package manifest (hosted entry), the
                          provenance the catalog provides and what is missing

Flags:
  --experimental-contextforge   required: acknowledges that this is a spike
  --catalog FILE                the catalog file (at most 4 MiB)
  --sha256 HEX                  refuse the file unless its SHA-256 matches
  --release TAG                 ContextForge release the file belongs to (import)
  --version V                   exact artifact version of a local entry (import)
  --artifact-sha256 HEX         artifact SHA-256 of a local entry (import)
  --class CLASS                 list only local, hosted or unsupported entries (list)
  --json                        JSON output (list; import always prints JSON)
`

func catalogCmd(args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "list" && args[0] != "import") {
		fmt.Fprint(out, catalogUsage)
		return errors.New("catalog: subcommand list or import required")
	}
	sub := args[0]
	fs := flag.NewFlagSet("catalog "+sub, flag.ContinueOnError)
	experimental := fs.Bool("experimental-contextforge", false, "acknowledge that the ContextForge catalog commands are an experimental spike")
	file := fs.String("catalog", "", "ContextForge mcp-catalog.yml")
	pin := fs.String("sha256", "", "expected SHA-256 of the catalog file")
	release := fs.String("release", "", "ContextForge release the catalog belongs to")
	version := fs.String("version", "", "exact artifact version (local entry)")
	artifactSHA := fs.String("artifact-sha256", "", "artifact SHA-256 (local entry)")
	class := fs.String("class", "", "list only this class")
	asJSON := fs.Bool("json", false, "JSON output")
	dryRun := fs.Bool("dry-run", false, "print the mapped draft only (the only mode)")
	// Flags may follow the entry ID.
	var pos []string
	rest := args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if !*experimental {
		return errors.New("catalog: the ContextForge catalog commands are an experimental spike; pass --experimental-contextforge")
	}
	if *file == "" {
		return errors.New("catalog: --catalog FILE is required (catalogs are read from local files only)")
	}
	raw, err := readCatalogFile(*file)
	if err != nil {
		return err
	}
	cat, err := contextforge.ParseCatalog(raw)
	if err != nil {
		return err
	}
	if *pin != "" && !strings.EqualFold(*pin, cat.SHA256) {
		return fmt.Errorf("catalog: %s has SHA-256 %s, not the expected %s", *file, cat.SHA256, strings.ToLower(*pin))
	}
	switch sub {
	case "list":
		if len(pos) != 0 {
			return fmt.Errorf("catalog list: unexpected argument %q", pos[0])
		}
		return catalogList(out, cat, *class, *asJSON, *pin != "")
	default:
		if !*dryRun {
			return errors.New("catalog import: only --dry-run is implemented in this spike")
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

func catalogList(out io.Writer, cat *contextforge.Catalog, only string, asJSON, pinned bool) error {
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
		return enc.Encode(map[string]any{"catalog_sha256": cat.SHA256, "sha256_confirmed": pinned, "entries": rows})
	}
	note := "not confirmed; pass --sha256 to pin it"
	if pinned {
		note = "confirmed"
	}
	fmt.Fprintf(out, "catalog sha256 %s (%s), %d of %d entries\n", cat.SHA256, note, len(rows), len(cat.Entries))
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
