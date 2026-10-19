package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func texts(us []UIString) []string {
	var out []string
	for _, u := range us {
		out = append(out, u.Text)
	}
	return out
}

func TestExtractJSX(t *testing.T) {
	src := `import { x } from "./seamless-module";
import "simply.css";
const re = /"just"/g;
// Seamless comment
/* Unlock comment */
const label = "Approve call";
const cls = "row-just is-on";
const url = "https://example.com/Unlock";
const t = ` + "`Held ${n} calls`" + `;
const tagged = css` + "`color: red; seamless`" + `;
const f = <T,>(a: T) => a < b;
export function V() {
  return (
    <div className="seamless" data-x="unlock" aria-label="Open console">
      <p title="Policy revision">Sign in again.</p>
      {ok ? <span>Gateway &quot;stopped&quot;</span> : "Not enforced"}
      <Foo label={cond ? "Retry" : "Cancel"} className={"just"} />
    </div>
  );
}
`
	got := texts(extractJS(src, true))
	want := []string{"Approve call", "row-just is-on", "Held {} calls", "Open console", "Policy revision", "Sign in again.", `Gateway "stopped"`, "Not enforced", "Retry", "Cancel"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extracted\n%q\nwant\n%q", got, want)
	}
}

func TestExtractLines(t *testing.T) {
	src := "const a = 1;\n\nconst b = \"Second\";\nconst c = <p>\n  Fourth line\n</p>;\n"
	got := extractJS(src, true)
	if len(got) != 2 || got[0].Line != 3 || got[1].Line != 5 {
		t.Errorf("lines: %+v", got)
	}
}

func TestExtractHTML(t *testing.T) {
	src := `<!doctype html><html><head><title>Gateway console</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="description" content="Seamless gateway" />
<script>const s = "Unlock";</script><style>.a{}</style><!-- Oops -->
</head><body><img alt="Tray state" src="/x.png"><p>Sign in &mdash; now</p></body></html>`
	got := texts(extractHTML(src))
	want := []string{"Gateway console", "Seamless gateway", "Tray state", "Sign in — now"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extracted %q, want %q", got, want)
	}
}

func TestExtractRust(t *testing.T) {
	src := `// "Unlock" in a comment
fn tray<'a>(x: &'a str) -> char {
    let title = "Gateway \u{2014} healthy";
    let raw = r#"Open "console""#;
    let id = "tray.open";
    '"'
}`
	got := texts(extractRust(src))
	want := []string{"Gateway — healthy", `Open "console"`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extracted %q, want %q", got, want)
	}
}

func TestExtractJSON(t *testing.T) {
	src := "{\n  \"messages\": {\n    \"FAIL_CLOSED\": {\"text\": \"The Gateway is not accepting tool calls.\", \"codes\": [\"-31004\"]},\n    \"tray\": [\"healthy\", \"Oops!\"]\n  },\n  \"version\": 1\n}\n"
	got := extractJSON(src)
	if !reflect.DeepEqual(texts(got), []string{"The Gateway is not accepting tool calls.", "-31004", "healthy", "Oops!"}) || got[0].Line != 3 || got[3].Line != 4 {
		t.Errorf("extracted %+v", got)
	}
	if fs := rules(lintFile("docs/design/messages.json", src)); !reflect.DeepEqual(fs, []string{"banned-word:Oops", "exclamation:s!"}) {
		t.Errorf("findings %q", fs)
	}
}

func rules(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule+":"+f.Match)
	}
	return out
}

func TestStringRules(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want []string
	}{
		{`const a = "Unlock seamless control";`, []string{"banned-word:Unlock", "banned-word:seamless"}},
		{`const a = "Simply sign in";`, []string{"banned-word:Simply"}},
		{`const a = "Don’t worry, it is saved";`, []string{"banned-word:Don’t worry"}},
		{`const a = "Let's get started";`, []string{"banned-word:Let's get started"}},
		{`const a = "AI-powered approvals";`, []string{"banned-word:AI-powered"}},
		{`const a = "Something went wrong";`, []string{"banned-word:Something went wrong"}},
		{`const a = "Saved!";`, []string{"exclamation:d!"}},
		{`const a = "Saved! Next";`, []string{"exclamation:d!"}},
		{`const a = "Done ✨";`, []string{"emoji:✨"}},
		{`const a = "Ready 🎉";`, []string{"emoji:🎉"}},
		{`const a = "Gateway — ready";`, []string{"em-dash:—"}},
		{"const a = `Calls — ${n}`;", []string{"em-dash:—"}},
		{`const s = { background: "linear-gradient(red, blue)" };`, []string{"css-gradient:linear-gradient"}},
		// Passes: the same words in code, identifiers and imports.
		{`import { justify } from "seamless"; const just = robust; if (a !== b) {}`, nil},
		{`const a = "Justify the elevated band";`, nil},
		{`const a = "just-in-time";`, nil},
		{`const a = "x !important";`, nil},
		{`const a = "Diamond ◆ shape";`, nil},
	} {
		got := rules(lintFile("console/src/x.tsx", tc.src))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestCSSRules(t *testing.T) {
	src := `/* linear-gradient( in a comment */
.a { background: linear-gradient(90deg, #7c3aed, #2563eb); }
.b { backdrop-filter: blur(8px); }
.c { text-shadow: 0 0 4px var(--focus); }
.d { box-shadow: 0 4px 12px rgba(0,0,0,.3); }
.e { box-shadow: inset 3px 0 0 var(--bad); }
.f { border-radius: 12px; }
.g { border-radius: 2px; }
.h { border-radius: 50%; }
.i { animation: pulse 1s infinite; }
.j { filter: drop-shadow(0 0 2px red); }
@media (prefers-reduced-motion: reduce) { * { animation: none !important; } }
`
	got := rules(lintCSS("site/src/app/x.css", src))
	want := []string{
		"css-gradient:linear-gradient",
		"css-backdrop-filter:backdrop-filter: blur(8px)",
		"css-text-shadow:text-shadow: 0 0 4px var(--focus)",
		"css-box-shadow:box-shadow: 0 4px 12px rgba(0,0,0,.3)",
		"css-radius:border-radius: 12px",
		"css-animation:animation: pulse 1s infinite",
		"css-filter:drop-shadow(",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
	if fs := lintCSS("x.css", src); fs[0].Line != 2 {
		t.Errorf("gradient line %d, want 2", fs[0].Line)
	}
}

func TestAllowlist(t *testing.T) {
	entries, err := parseAllowlist("# comment\n\nconsole/src/a.tsx banned-word robust  # statistics term\nconsole/src/a.tsx banned-word rest assured  # quoted\nsite/src/b.tsx emoji 🎉  # stale\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[1].Match != "rest assured" || entries[0].Reason != "statistics term" {
		t.Fatalf("entries %+v", entries)
	}
	findings := []Finding{
		{Path: "console/src/a.tsx", Line: 1, Rule: "banned-word", Match: "Robust"},
		{Path: "console/src/a.tsx", Line: 2, Rule: "banned-word", Match: "Rest  assured"},
		{Path: "console/src/a.tsx", Line: 3, Rule: "banned-word", Match: "seamless"},
		{Path: "console/src/other.tsx", Line: 1, Rule: "banned-word", Match: "robust"},
	}
	rest, stale := applyAllowlist(findings, entries)
	if len(rest) != 2 || rest[0].Match != "seamless" || rest[1].Path != "console/src/other.tsx" {
		t.Errorf("rest %+v", rest)
	}
	if len(stale) != 1 || stale[0].Path != "site/src/b.tsx" {
		t.Errorf("stale %+v", stale)
	}
	for _, bad := range []string{
		"console/src/a.tsx banned-word robust",            // no reason
		"console/src/a.tsx banned-word robust  #   ",      // empty reason
		"console/src/a.tsx no-such-rule robust  # reason", // unknown rule
		"console/src/a.tsx banned-word  # reason",         // no match text
	} {
		if _, err := parseAllowlist(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestRunFixtureTree runs the whole command on a temporary tree: a banned
// phrase fails, an allowlisted one passes, and a stale entry fails.
func TestRunFixtureTree(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("console/src/a.tsx", `export const A = () => <p>Robust statistics</p>;`)
	write("console/src/a.test.tsx", `const s = "Unlock";`)
	write("console/src/node_modules/x.ts", `const s = "Unlock";`)
	write("desktop/src-tauri/src/main.rs", `fn main() { let s = "Oops, the tray failed"; }`)
	write("desktop/src-tauri/target/x.rs", `fn main() { let s = "Oops"; }`)
	write("site/src/app/x.css", `.a { backdrop-filter: blur(4px); }`)
	write("docs/design/messages.json", `{"SAVED": "Saved, rest assured."}`)
	write(DefaultAllowlist, "console/src/a.tsx banned-word robust  # statistics term\n")

	var out bytes.Buffer
	code, err := run(root, DefaultAllowlist, &out)
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if code != 1 ||
		!strings.Contains(got, "desktop/src-tauri/src/main.rs:1: banned-word: Oops\n") ||
		!strings.Contains(got, "site/src/app/x.css:1: css-backdrop-filter: backdrop-filter: blur(4px)\n") ||
		!strings.Contains(got, "docs/design/messages.json:1: banned-word: rest assured\n") ||
		strings.Contains(got, "Robust") || strings.Contains(got, "a.test.tsx") || strings.Contains(got, "node_modules") || strings.Contains(got, "target") {
		t.Errorf("code %d, output:\n%s", code, got)
	}

	write("desktop/src-tauri/src/main.rs", `fn main() { let s = "The tray could not start."; }`)
	write("site/src/app/x.css", `.a { border: 1px solid var(--rule); }`)
	write("console/src/a.tsx", `export const A = () => <p>Median statistics</p>;`)
	write("docs/design/messages.json", `{"SAVED": "Policy revision published."}`)
	out.Reset()
	if code, _ := run(root, DefaultAllowlist, &out); code != 1 || !strings.Contains(out.String(), "stale allowlist entry") {
		t.Errorf("stale entry: code %d, output:\n%s", code, out.String())
	}

	write(DefaultAllowlist, "# empty\n")
	out.Reset()
	if code, _ := run(root, DefaultAllowlist, &out); code != 0 {
		t.Errorf("clean tree: code %d, output:\n%s", code, out.String())
	}
}

// TestRepositoryClean is FR-20.51 (planned v1.3.0): the UI strings of
// console/, site/ and desktop/ (when present) follow docs/design/writing.md,
// the stylesheets avoid the banned patterns of docs/design/visual.md, every
// exception is in the allowlist with a reason and no allowlist entry is
// stale. The CI job "lint" runs the same check with `go run ./tools/uilint`.
func TestRepositoryClean(t *testing.T) {
	reqtest.Verifies(t, "FR-20.51")
	root := filepath.Join("..", "..")
	files, err := collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 40 {
		t.Fatalf("only %d files in scope; the scope is broken", len(files))
	}
	var out bytes.Buffer
	code, err := run(root, DefaultAllowlist, &out)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Errorf("uilint found problems (fix the string or add an allowlist entry with a reason):\n%s", out.String())
	}
}
