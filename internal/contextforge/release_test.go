package contextforge

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The release lock compiled into the Gateway is the file the release
// publishes.
func TestLockCopyMatchesPackaging(t *testing.T) {
	pub, err := os.ReadFile(filepath.Join("..", "..", "packaging", "contextforge.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, lockJSON) {
		t.Fatal("internal/contextforge/release/contextforge.lock.json differs from packaging/contextforge.lock.json; copy the packaging file")
	}
}

// FR-22.18 (part): the lock pins one release with its image index and both
// Linux platform digests, the catalog SHA-256, the signer identity and the
// starter set. Not covered here: the wheel set of the managed-process form
// (empty until FR-22.20 is built) and the lock's signature with the release
// key, which the release workflow adds.
func TestReleaseLock(t *testing.T) {
	reqtest.Partial(t, "FR-22.18", "FR-22.17")
	l := ReleaseLock()
	r := l.ContextForge
	if r.Version != "v1.0.11" || r.Source.Tag != r.Version || r.License != "Apache-2.0" {
		t.Fatalf("release %+v", r)
	}
	if r.Image.IndexDigest != "sha256:e9639c030162d6cb2f9f188600dd69af8091ec62a7ce307d4a74f4d4f86873df" {
		t.Fatalf("index digest %s", r.Image.IndexDigest)
	}
	if got := r.ImageRef("linux/arm64"); got != "ghcr.io/ibm/mcp-context-forge@sha256:c081736abaf4864af4014a743b2a82447a6de64ec4e6881ea12b77aa1a43554f" {
		t.Fatalf("arm64 ref %s", got)
	}
	if r.ImageRef("linux/s390x") != "" {
		t.Fatal("unpinned platform has a reference")
	}
	if r.Catalog.SHA256 != fixtureSHA256 || r.Catalog.Entries != 135 {
		t.Fatalf("catalog %+v", r.Catalog)
	}
	if !strings.HasSuffix(r.Signer.Subject, "docker-multiplatform.yml@refs/tags/v1.0.11") {
		t.Fatalf("signer %+v", r.Signer)
	}
	c, err := PinnedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	// FR-22.17 (part): the starter set is in the catalog, hosted and Open.
	// Its read-only tools and the one-import offer need the probe.
	if err := l.CheckStarterSet(c); err != nil {
		t.Fatal(err)
	}
	if len(r.StarterSet) == 0 {
		t.Fatal("empty starter set")
	}
}

func TestParseLockRefusals(t *testing.T) {
	mutate := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(lockJSON, &m); err != nil {
			t.Fatal(err)
		}
		f(m["contextforge"].(map[string]any))
		raw, _ := json.Marshal(m)
		return raw
	}
	cases := map[string][]byte{
		"floating tag": mutate(func(m map[string]any) { m["version"] = "latest" }),
		"tag mismatch": mutate(func(m map[string]any) { m["source"].(map[string]any)["tag"] = "v1.0.10" }),
		"short commit": mutate(func(m map[string]any) { m["source"].(map[string]any)["commit"] = "077071b" }),
		"index digest": mutate(func(m map[string]any) { m["image"].(map[string]any)["index_digest"] = "v1.0.11" }),
		"missing arm64": mutate(func(m map[string]any) {
			delete(m["image"].(map[string]any)["platforms"].(map[string]any), "linux/arm64")
		}),
		"other workflow": mutate(func(m map[string]any) {
			m["signer"].(map[string]any)["subject"] = "https://github.com/evil/fork/.github/workflows/x.yml@refs/tags/v1.0.11"
		}),
		"other tag signer": mutate(func(m map[string]any) {
			m["signer"].(map[string]any)["subject"] = "https://github.com/IBM/mcp-context-forge/.github/workflows/docker-multiplatform.yml@refs/heads/main"
		}),
		"other issuer":   mutate(func(m map[string]any) { m["signer"].(map[string]any)["issuer"] = "https://accounts.example" }),
		"catalog digest": mutate(func(m map[string]any) { m["catalog"].(map[string]any)["sha256"] = "abc" }),
		"bad wheel": mutate(func(m map[string]any) {
			m["wheels"] = []any{map[string]any{"file": "x.tar.gz", "sha256": strings.Repeat("a", 64)}}
		}),
		"unsorted starter": mutate(func(m map[string]any) { m["starter_set"] = []any{"b", "a"} }),
		"unknown member":   mutate(func(m map[string]any) { m["extra"] = true }),
		"no license":       mutate(func(m map[string]any) { m["license"] = "" }),
	}
	for name, raw := range cases {
		_, err := ParseLock(raw)
		if packaging.ReasonOf(err) != ReasonLockInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStarterSetChecks(t *testing.T) {
	c, err := PinnedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"markitdown", "cortex", "asana", "no-such-entry"} { // local, API key, OAuth, missing
		l := ReleaseLock()
		l.ContextForge.StarterSet = []string{id}
		if err := l.CheckStarterSet(c); packaging.ReasonOf(err) != ReasonLockInvalid {
			t.Errorf("%s accepted in the starter set: %v", id, err)
		}
	}
}

// FR-22.1 (part): the pinned catalog loads; a pinned file with one byte
// changed and an operator file without, or with a wrong, confirmed digest
// are refused with CATALOG_DIGEST_MISMATCH before parsing; an operator file
// with the confirmed digest loads. The catalog code imports no network
// client (see TestCatalogCodeHasNoNetworkOrExec). Not covered here: the
// Connector inside a running Gateway with outbound access blocked.
func TestCatalogSource(t *testing.T) {
	reqtest.Partial(t, "FR-22.1")
	c, err := PinnedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if c.Origin != OriginPinned || c.Release != "v1.0.11" || len(c.Entries) != 135 {
		t.Fatalf("pinned catalog %s %s %d", c.Origin, c.Release, len(c.Entries))
	}
	changed := append([]byte(nil), pinnedCatalogYAML...)
	i := bytes.Index(changed, []byte("DeepWiki"))
	changed[i] = 'd'
	if _, err := LoadPinned(changed, ReleaseLock()); packaging.ReasonOf(err) != ReasonCatalogDigestMismatch {
		t.Fatalf("changed pinned file: %v", err)
	}
	op := []byte("catalog_servers:\n  - id: own\n    name: Own\n    provider: Me\n    auth_type: Open\n    url: https://mcp.example.com/mcp\n")
	sum := packaging.SHA256Hex(op)
	got, err := LoadConfirmed(op, strings.ToUpper(sum))
	if err != nil || got.Origin != OriginOperator || got.Entries[0].ID != "own" {
		t.Fatalf("confirmed operator file: %v", err)
	}
	for _, confirmed := range []string{"", fixtureSHA256, "not-hex"} {
		if _, err := LoadConfirmed(op, confirmed); packaging.ReasonOf(err) != ReasonCatalogDigestMismatch {
			t.Errorf("operator file with confirmation %q: %v", confirmed, err)
		}
	}
	// The digest is checked before parsing: an unconfirmed alias bomb is
	// refused for its digest, not parsed.
	if _, err := LoadConfirmed([]byte("a: &a [*a]"), ""); packaging.ReasonOf(err) != ReasonCatalogDigestMismatch {
		t.Fatalf("unconfirmed bomb: %v", err)
	}
}

// FR-22.2: every bound and rule refuses the whole file within 1 second
// with the violated rule named, and the parser's memory use stays below
// 64 MiB. HFC-02 is the alias case.
func TestBoundedParsing(t *testing.T) {
	reqtest.Verifies(t, "FR-22.2")
	var bomb strings.Builder
	bomb.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 12; i++ {
		bomb.WriteString("a" + strconv.Itoa(i) + ": &a" + strconv.Itoa(i) + " [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				bomb.WriteString(", ")
			}
			bomb.WriteString("*a" + strconv.Itoa(i-1))
		}
		bomb.WriteString("]\n")
	}
	bomb.WriteString("catalog_servers:\n  - id: y\n    tags: *a11\n")
	var many strings.Builder
	many.WriteString("catalog_servers:\n")
	for i := 0; i <= MaxEntries; i++ {
		many.WriteString("  - id: e" + strconv.Itoa(i) + "\n")
	}
	cases := []struct{ name, doc, rule string }{
		{"size", "catalog_servers: []\n#" + strings.Repeat("x", MaxCatalogBytes), "bytes, more than"},
		{"entries", many.String(), "entries, more than"},
		{"string", "catalog_servers:\n  - id: y\n    description: " + strings.Repeat("a", MaxStringChars+1) + "\n", "longer than 4096"},
		{"alias expansion", bomb.String(), "is not allowed"},
		{"custom tag", "catalog_servers:\n  - id: !evil y\n", "explicit tag"},
		{"merge key", "base: {url: u}\ncatalog_servers:\n  - id: y\n    <<: {url: v}\n", "merge key"},
	}
	for _, tc := range cases {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		_, err := ParseCatalog([]byte(tc.doc))
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		if packaging.ReasonOf(err) != ReasonCatalogInvalid || !strings.Contains(err.Error(), tc.rule) {
			t.Errorf("%s: %v, want CATALOG_INVALID naming %q", tc.name, err, tc.rule)
		}
		if took > time.Second {
			t.Errorf("%s: refused after %v", tc.name, took)
		}
		// TotalAlloc counts every allocation, an upper bound on the rise.
		if rise := after.TotalAlloc - before.TotalAlloc; rise > 64<<20 {
			t.Errorf("%s: allocated %d MiB", tc.name, rise>>20)
		}
	}
}

// FR-22.7 (part) and FR-22.1 (part): the catalog code cannot run an
// install string or fetch anything: it imports no process, shell or
// network client package.
func TestCatalogCodeHasNoNetworkOrExec(t *testing.T) {
	reqtest.Partial(t, "FR-22.7")
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]bool{"os/exec": true, "net/http": true, "syscall": true, "net/rpc": true, "plugin": true}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if refused[p] {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
