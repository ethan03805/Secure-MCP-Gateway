package edge

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// catalogue is docs/design/messages.json, the message catalogue the console
// and the desktop application share (FR-20.48).
type catalogue struct {
	Version     int `json:"version"`
	ReasonCodes map[string]struct {
		Codes   []int64 `json:"codes"`
		Message string  `json:"message"`
	} `json:"reasonCodes"`
	Desktop struct {
		States map[string]struct {
			Label   string `json:"label"`
			Meaning string `json:"meaning"`
			Action  string `json:"action"`
			Detail  string `json:"detail"`
			Control string `json:"control"`
		} `json:"states"`
		Labels map[string]struct {
			Label   string `json:"label"`
			Meaning string `json:"meaning"`
		} `json:"labels"`
		Errors map[string]catalogueEntry `json:"errors"`
		Empty  map[string]catalogueEntry `json:"empty"`
	} `json:"desktop"`
}

type catalogueEntry struct {
	Title string `json:"title"`
	What  string `json:"what"`
	Why   string `json:"why"`
	Todo  string `json:"todo"`
}

func loadCatalogue(t *testing.T) catalogue {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	// $comment is the only top-level key outside the struct; every other
	// unknown field is an error, so a misspelt part cannot pass unchecked.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	delete(top, "$comment")
	stripped, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(stripped))
	dec.DisallowUnknownFields()
	var c catalogue
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("docs/design/messages.json: %v", err)
	}
	return c
}

// TestMessageCatalogue: the shared catalogue holds every reason code of
// Appendix B Table B.2 with the error builder's message word for word and
// its error codes, and every desktop tray state, error and empty state has
// the parts FR-20.45 to FR-20.47 require (FR-20.48). Whether the console
// and desktop builds read their text from it is checked by their own
// builds; this test covers the catalogue against the Gateway.
func TestMessageCatalogue(t *testing.T) {
	reqtest.Partial(t, "FR-20.48")
	checkCatalogue(t)
}

// checkCatalogue is TestMessageCatalogue's check of the catalogue against
// the Gateway's error builder and the desktop parts.
func checkCatalogue(t *testing.T) catalogue {
	t.Helper()
	c := loadCatalogue(t)
	if c.Version != 1 {
		t.Errorf("version %d, want 1", c.Version)
	}
	for reason, msg := range reasonMessages {
		e, ok := c.ReasonCodes[reason]
		if !ok {
			t.Errorf("%s: missing from the catalogue", reason)
			continue
		}
		if e.Message != msg {
			t.Errorf("%s: catalogue %q, error builder %q", reason, e.Message, msg)
		}
		if len(e.Codes) == 0 {
			t.Errorf("%s: no error code", reason)
		}
		for _, code := range e.Codes {
			if code > -31000 || code < -32768 {
				t.Errorf("%s: code %d outside the Gateway and JSON-RPC ranges", reason, code)
			}
		}
	}
	for reason := range c.ReasonCodes {
		if _, ok := reasonMessages[reason]; !ok {
			t.Errorf("%s: in the catalogue but not a Table B.2 reason code", reason)
		}
	}

	sentences := func(s string) int { return strings.Count(strings.TrimSpace(s), ". ") + 1 }

	// The seven tray states of FR-20.2, plus the variant for a degraded
	// Gateway that is not labelled enforced and has a cause besides the
	// profile's own (a Standalone installation is never healthy, FR-13.10).
	controls := map[string]bool{"open-console": true, "start": true, "restart": true}
	for _, s := range []string{"healthy", "running", "degraded", "degraded-not-enforced", "fail-closed", "emergency-stop", "stopped", "unreachable"} {
		st, ok := c.Desktop.States[s]
		if !ok {
			t.Errorf("tray state %s: missing", s)
			continue
		}
		if st.Label == "" || st.Meaning == "" || st.Action == "" {
			t.Errorf("tray state %s: label, meaning and action are required", s)
		}
		if sentences(st.Meaning) > 2 || sentences(st.Action) > 2 {
			t.Errorf("tray state %s: meaning and action take two sentences at most", s)
		}
		if !controls[st.Control] {
			t.Errorf("tray state %s: control %q is not an application control", s, st.Control)
		}
	}
	if c.Desktop.States["stopped"].Control != "start" {
		t.Error("stopped: the control must be start (FR-20.45)")
	}
	for _, s := range []string{"fail-closed", "emergency-stop", "degraded"} {
		if c.Desktop.States[s].Control != "open-console" {
			t.Errorf("%s: the control must be open-console (FR-20.45)", s)
		}
	}
	if !strings.Contains(c.Desktop.States["unreachable"].Detail, "{lastReading}") {
		t.Error("unreachable: the detail shows the time of the last reading (FR-20.45)")
	}
	if c.Desktop.States["unreachable"].Label == c.Desktop.States["healthy"].Label {
		t.Error("unreachable must not read as healthy (FR-20.4)")
	}
	if l := c.Desktop.Labels["not-enforced"]; l.Label != "not enforced" || l.Meaning == "" {
		t.Error("labels.not-enforced: the label is `not enforced` and needs a meaning (FR-20.45)")
	}

	code := regexp.MustCompile(`^[A-Z][A-Z_]+$`)
	for kind, set := range map[string]map[string]catalogueEntry{"errors": c.Desktop.Errors, "empty": c.Desktop.Empty} {
		if len(set) == 0 {
			t.Errorf("desktop.%s is empty", kind)
		}
		for id, e := range set {
			if !code.MatchString(id) {
				t.Errorf("desktop.%s.%s: code is not UPPER_SNAKE_CASE", kind, id)
			}
			if _, clash := c.ReasonCodes[id]; clash {
				t.Errorf("desktop.%s.%s: collides with a Gateway reason code", kind, id)
			}
			if e.Title == "" || e.What == "" || e.Todo == "" {
				t.Errorf("desktop.%s.%s: title, what and todo are required", kind, id)
			}
			// FR-20.47: one sentence for what happened, at most one for why
			// and at most two for what to do.
			if sentences(e.What) > 1 || e.Why != "" && sentences(e.Why) > 1 || sentences(e.Todo) > 2 {
				t.Errorf("desktop.%s.%s: what, why and todo take one, one and two sentences at most", kind, id)
			}
			if strings.HasSuffix(e.Title, ".") {
				t.Errorf("desktop.%s.%s: a title ends without a full stop", kind, id)
			}
		}
	}
	return c
}

// TestCatalogueIsTheOnlySource: the console and the desktop application
// take every reason-code message, desktop error, empty state and tray
// state text from docs/design/messages.json at build time and hold no
// copy of it (FR-20.48). With checkCatalogue (every Table B.2 reason code
// with the error builder's text, every desktop part) this covers the
// whole verification statement:
//   - the console imports the catalogue (console/src/messages.ts), the
//     desktop windows' build writes dist/catalogue.js from it
//     (desktop/scripts/copy-static.mjs) and the windows import that, and
//     the Rust core compiles it in (include_str!);
//   - no source file of the console, the desktop windows or the Rust core
//     (tests aside) contains a catalogue text, so none can drift from it;
//   - every desktop code the sources raise has a catalogue entry.
func TestCatalogueIsTheOnlySource(t *testing.T) {
	reqtest.Verifies(t, "FR-20.48")
	c := checkCatalogue(t)
	root := filepath.Join("..", "..")
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	for file, want := range map[string]string{
		"console/src/messages.ts":          `from "../../docs/design/messages.json"`,
		"desktop/scripts/copy-static.mjs":  `"docs", "design", "messages.json"`,
		"desktop/src-tauri/src/explain.rs": `include_str!("../../../docs/design/messages.json")`,
		"desktop/src/status-view.ts":       `import { catalogue } from "./catalogue.js"`,
		"desktop/src/setup-view.ts":        `import { catalogue } from "./catalogue.js"`,
		"desktop/src/clients-view.ts":      `import { catalogue } from "./catalogue.js"`,
		"desktop/src/updates-view.ts":      `import { catalogue } from "./catalogue.js"`,
	} {
		if !strings.Contains(read(file), want) {
			t.Errorf("%s does not take its text from the catalogue (%s)", file, want)
		}
	}

	// The catalogue's texts, each as its longest run without a parameter.
	var texts []string
	param := regexp.MustCompile(`\{[a-zA-Z]+\}`)
	add := func(s string) {
		longest := ""
		for _, part := range param.Split(s, -1) {
			if part = strings.TrimSpace(part); len(part) > len(longest) {
				longest = part
			}
		}
		// Short texts ("healthy", "Close") are words, not copies.
		if len(longest) >= 24 {
			texts = append(texts, longest)
		}
	}
	for _, e := range c.ReasonCodes {
		add(e.Message)
	}
	for _, st := range c.Desktop.States {
		add(st.Meaning)
		add(st.Action)
		add(st.Detail)
	}
	for _, l := range c.Desktop.Labels {
		add(l.Meaning)
	}
	for _, set := range []map[string]catalogueEntry{c.Desktop.Errors, c.Desktop.Empty} {
		for _, e := range set {
			add(e.What)
			add(e.Why)
			add(e.Todo)
		}
	}
	if len(texts) < 50 {
		t.Fatalf("only %d catalogue texts to look for", len(texts))
	}

	desktopCode := regexp.MustCompile(`"((?:SETUP|CLIENTS?|SERVICE|UPDATES?|UPGRADE|CONSOLE|ELEVATION|APPROVALS)_[A-Z0-9_]+)"`)
	files := 0
	for _, dir := range []string{"console/src", "desktop/src", "desktop/src-tauri/src"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			name := d.Name()
			ext := filepath.Ext(name)
			if (ext != ".ts" && ext != ".tsx" && ext != ".rs" && ext != ".html") || strings.Contains(name, ".test.") ||
				name == "catalogue.d.ts" || name == "config_tests.rs" || name == "claims.rs" {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			// A Rust file's tests may quote the catalogue to check it.
			src, _, _ := strings.Cut(strings.ReplaceAll(string(b), "\r\n", "\n"), "#[cfg(test)]\nmod tests")
			rel, _ := filepath.Rel(root, p)
			for _, text := range texts {
				if strings.Contains(src, text) {
					t.Errorf("%s holds a copy of the catalogue text %q", rel, text)
				}
			}
			if strings.HasPrefix(rel, "desktop") {
				for _, m := range desktopCode.FindAllStringSubmatch(src, -1) {
					_, isErr := c.Desktop.Errors[m[1]]
					_, isEmpty := c.Desktop.Empty[m[1]]
					if !isErr && !isEmpty {
						t.Errorf("%s raises %s, which has no catalogue entry", rel, m[1])
					}
				}
			}
			files++
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 40 {
		t.Fatalf("only %d source files checked", files)
	}
	t.Logf("%d catalogue texts looked for in %d source files", len(texts), files)
}
