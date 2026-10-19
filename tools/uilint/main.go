// Command uilint checks the user interface strings of the console, the
// desktop application and the reference site against the writing style guide
// (docs/design/writing.md) and the stylesheets against the banned visual
// patterns of the visual design guide (docs/design/visual.md). SRS FR-20.51
// (planned for v1.3.0).
//
// It extracts string literals, template literal text and JSX text from
// TypeScript and JavaScript sources, text and user-facing attributes from
// HTML, string literals from Rust, and declarations from CSS. It prints one
// line per finding, "path:line: rule: matched text", and exits 1 when there
// is a finding or a stale allowlist entry.
//
// Usage:
//
//	go run ./tools/uilint [-root .] [-allowlist docs/design/ui-string-allowlist.txt]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultAllowlist is the allowlist path relative to the repository root.
const DefaultAllowlist = "docs/design/ui-string-allowlist.txt"

func main() {
	root := flag.String("root", ".", "repository root")
	allow := flag.String("allowlist", DefaultAllowlist, "allowlist file, relative to -root")
	dump := flag.Bool("strings", false, "print every extracted UI string instead of linting (to review the extractor)")
	flag.Parse()
	if *dump {
		if err := dumpStrings(*root, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "uilint:", err)
			os.Exit(2)
		}
		return
	}
	code, err := run(*root, *allow, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "uilint:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

// Finding is one rule violation.
type Finding struct {
	Path  string // slash-separated, relative to the repository root
	Line  int
	Rule  string
	Match string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.Path, f.Line, f.Rule, f.Match)
}

// run lints the repository at root and writes the findings to w. It returns
// the exit code: 0 when clean, 1 on findings or stale allowlist entries.
func run(root, allowPath string, w io.Writer) (int, error) {
	files, err := collect(root)
	if err != nil {
		return 2, err
	}
	var findings []Finding
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return 2, err
		}
		findings = append(findings, lintFile(rel, string(b))...)
	}
	var entries []AllowEntry
	if b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(allowPath))); err == nil {
		entries, err = parseAllowlist(string(b))
		if err != nil {
			return 2, fmt.Errorf("%s: %w", allowPath, err)
		}
	} else if !os.IsNotExist(err) {
		return 2, err
	}
	rest, stale := applyAllowlist(findings, entries)
	for _, f := range rest {
		fmt.Fprintln(w, f)
	}
	for _, e := range stale {
		fmt.Fprintf(w, "%s:%d: stale allowlist entry (matches nothing): %s %s %s\n", allowPath, e.Line, e.Path, e.Rule, e.Match)
	}
	if len(rest) > 0 || len(stale) > 0 {
		fmt.Fprintf(w, "uilint: %d finding(s), %d stale allowlist entr(ies); see docs/design/writing.md and docs/design/visual.md\n", len(rest), len(stale))
		return 1, nil
	}
	return 0, nil
}

// dumpStrings prints every extracted UI string as "path:line: text".
func dumpStrings(root string, w io.Writer) error {
	files, err := collect(root)
	if err != nil {
		return err
	}
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		for _, s := range extract(rel, string(b)) {
			fmt.Fprintf(w, "%s:%d: %s\n", rel, s.Line, s.Text)
		}
	}
	return nil
}

// Scope ------------------------------------------------------------------

// scope lists the trees the lint reads and the extensions it reads in each.
var scope = []struct {
	dir  string
	exts []string
}{
	{"console/src", []string{".ts", ".tsx", ".css"}},
	{"site/src", []string{".ts", ".tsx", ".css"}},
	{"site/public", []string{".html"}},
	{"desktop", []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".html", ".rs", ".css"}},
}

// scopeFiles are single files in scope, read when present. Every string
// value of the shared message catalogue (FR-20.48) is UI text.
var scopeFiles = []string{"console/index.html", "docs/design/messages.json"}

// skipDirs are directory names never descended into: dependencies, build
// outputs and generated code.
var skipDirs = map[string]bool{
	"node_modules": true, "target": true, "dist": true, "gen": true, "build": true,
	".next": true, "out": true, "e2e": true, "test": true, "tests": true, "__tests__": true,
}

func isTestFile(name string) bool {
	return strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") || strings.HasSuffix(name, ".d.ts")
}

// collect returns the in-scope files under root, sorted, slash-separated.
func collect(root string) ([]string, error) {
	var out []string
	for _, f := range scopeFiles {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f))); err == nil {
			out = append(out, f)
		}
	}
	for _, s := range scope {
		base := filepath.Join(root, filepath.FromSlash(s.dir))
		if _, err := os.Stat(base); err != nil {
			continue // desktop/ does not exist before v1.3.0
		}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != base && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if isTestFile(d.Name()) {
				return nil
			}
			ext := filepath.Ext(d.Name())
			for _, e := range s.exts {
				if e == ext {
					rel, err := filepath.Rel(root, p)
					if err != nil {
						return err
					}
					out = append(out, filepath.ToSlash(rel))
					break
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// lintFile extracts the UI strings of one file and applies the rules.
func lintFile(rel, src string) []Finding {
	if filepath.Ext(rel) == ".css" {
		return lintCSS(rel, src)
	}
	var out []Finding
	for _, s := range extract(rel, src) {
		for _, m := range checkString(s.Text) {
			out = append(out, Finding{Path: rel, Line: s.Line, Rule: m.rule, Match: m.text})
		}
	}
	return out
}

// extract returns the UI strings of a non-CSS file.
func extract(rel, src string) []UIString {
	switch filepath.Ext(rel) {
	case ".tsx", ".jsx":
		return extractJS(src, true)
	case ".ts", ".js", ".mjs":
		return extractJS(src, false)
	case ".html":
		return extractHTML(src)
	case ".rs":
		return extractRust(src)
	case ".json":
		return extractJSON(src)
	}
	return nil
}

// Rules ------------------------------------------------------------------

// Banned lists the banned words and phrases of docs/design/writing.md. Each
// entry is a regular expression fragment matched case-insensitively as a
// whole word, where letters, digits, "_" and "-" are word characters, so
// "just" does not match "justify" or "just-in-time". A space matches any run
// of white space and "'" matches a straight or curly apostrophe.
var Banned = []string{
	"unlock(s|ed|ing)?",
	"seamless(ly)?",
	"effortless(ly)?",
	"supercharge(s|d)?",
	"elevate(s)?", "elevating",
	"empower(s|ed|ing)?",
	"leverage(s|d)?",
	"delve(s)?",
	"robust(ly)?",
	"cutting-edge", "cutting edge",
	"game-changer", "game changer", "game-changing",
	"let's get started", "let's go",
	"ai-powered", "powered by ai",
	"magic", "magical", "magically",
	"don't worry", "no worries", "rest assured",
	"simply", "just", "easily", "basically", "actually",
	"oops", "whoops", "uh-oh", "oh no", "something went wrong",
	"revolutionary", "revolutionize(s|d)?",
	"next-generation", "next-gen",
	"world-class", "best-in-class", "state-of-the-art",
	"harness the power", "unleash(es|ed)?",
	"streamline(s|d)?",
	"in today's",
	"journey",
	"blazing(-| )fast",
}

var bannedRes = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, b := range Banned {
		p := strings.ReplaceAll(b, " ", `\s+`)
		p = strings.ReplaceAll(p, "'", `['’]`)
		out = append(out, regexp.MustCompile(`(?i)(?:^|[^\pL\pN_-])(`+p+`)(?:$|[^\pL\pN_-])`))
	}
	return out
}()

// exclamationRe is an exclamation mark that ends a sentence: after a letter,
// digit, ")" or "?", and followed by white space or the end of the string.
var exclamationRe = regexp.MustCompile(`[\pL\pN)?]!+(?:\s|$)`)

// cssGradientRe also catches gradients in inline style strings.
var cssGradientRe = regexp.MustCompile(`(?i)\b((?:repeating-)?(?:linear|radial|conic)-gradient)\(`)

type match struct{ rule, text string }

// checkString applies the string rules to one UI string.
func checkString(s string) []match {
	var out []match
	for _, re := range bannedRes {
		for i := 0; i < len(s); {
			loc := re.FindStringSubmatchIndex(s[i:])
			if loc == nil {
				break
			}
			out = append(out, match{"banned-word", strings.Join(strings.Fields(s[i+loc[2]:i+loc[3]]), " ")})
			i += loc[3]
		}
	}
	for _, m := range exclamationRe.FindAllString(s, -1) {
		out = append(out, match{"exclamation", strings.TrimSpace(m)})
	}
	for _, r := range s {
		switch {
		case r == '—':
			out = append(out, match{"em-dash", "—"})
		case isEmoji(r):
			out = append(out, match{"emoji", string(r)})
		}
	}
	for _, m := range cssGradientRe.FindAllStringSubmatch(s, -1) {
		out = append(out, match{"css-gradient", strings.ToLower(m[1])})
	}
	return out
}

// isEmoji reports whether r is a pictographic emoji or dingbat: the
// Unicode Extended_Pictographic blocks, without the arrows, (c), (R) and TM
// signs, which have ordinary text uses, plus the emoji variation selector.
// Geometric shapes (U+25A0 to U+25FF), which the console uses as state
// shapes, are not emoji.
func isEmoji(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF: // emoticons, pictographs, transport, symbols
		return true
	case r >= 0x2600 && r <= 0x27BF: // miscellaneous symbols and dingbats (includes the sparkle U+2728)
		return true
	case r >= 0x2B05 && r <= 0x2B07, r == 0x2B1B, r == 0x2B1C, r == 0x2B50, r == 0x2B55:
		return true
	case r == 0x231A, r == 0x231B, r == 0x23F0, r == 0x23F3, r >= 0x23E9 && r <= 0x23EF:
		return true
	case r == 0xFE0F, r == 0x203C, r == 0x2049:
		return true
	}
	return false
}

// CSS rules ---------------------------------------------------------------

var (
	cssDeclRe   = regexp.MustCompile(`(?i)(^|[;{\s])(-webkit-backdrop-filter|backdrop-filter|text-shadow|box-shadow|filter|border(?:-(?:top|bottom|start|end))?(?:-(?:left|right|start|end))?-radius|animation|animation-iteration-count)\s*:\s*([^;}]*)`)
	cssLengthRe = regexp.MustCompile(`(?i)(\d*\.?\d+)(px|rem|em)\b`)
	cssFilterRe = regexp.MustCompile(`(?i)\b(blur|drop-shadow)\(`)
	cssInfRe    = regexp.MustCompile(`(?i)\binfinite\b`)
)

// lintCSS applies the banned visual pattern rules of docs/design/visual.md
// to a stylesheet.
func lintCSS(rel, src string) []Finding {
	src = blankComments(src, "/*", "*/")
	lines := lineIndex(src)
	var out []Finding
	add := func(off int, rule, text string) {
		out = append(out, Finding{Path: rel, Line: lines.line(off), Rule: rule, Match: text})
	}
	for _, m := range cssGradientRe.FindAllStringSubmatchIndex(src, -1) {
		add(m[0], "css-gradient", strings.ToLower(src[m[2]:m[3]]))
	}
	for _, m := range cssDeclRe.FindAllStringSubmatchIndex(src, -1) {
		prop := strings.ToLower(src[m[4]:m[5]])
		val := strings.Join(strings.Fields(src[m[6]:m[7]]), " ")
		lval := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(val, "!important")), " "))
		if lval == "none" || lval == "" || lval == "initial" || lval == "unset" || lval == "inherit" {
			continue
		}
		off := m[4]
		switch {
		case strings.HasSuffix(prop, "backdrop-filter"):
			add(off, "css-backdrop-filter", prop+": "+val)
		case prop == "text-shadow":
			add(off, "css-text-shadow", prop+": "+val)
		case prop == "box-shadow":
			for _, part := range splitTop(lval) {
				if !strings.Contains(part, "inset") {
					add(off, "css-box-shadow", prop+": "+val)
					break
				}
			}
		case prop == "filter":
			if fm := cssFilterRe.FindStringSubmatch(lval); fm != nil {
				add(off, "css-filter", fm[1]+"(")
			}
		case strings.HasSuffix(prop, "radius"):
			for _, lm := range cssLengthRe.FindAllStringSubmatch(lval, -1) {
				n, err := strconv.ParseFloat(lm[1], 64)
				if err != nil {
					continue
				}
				if lm[2] != "px" {
					n *= 16
				}
				if n > 4 {
					add(off, "css-radius", prop+": "+val)
					break
				}
			}
		case strings.HasPrefix(prop, "animation"):
			if cssInfRe.MatchString(lval) {
				add(off, "css-animation", prop+": "+val)
			}
		}
	}
	return out
}

// splitTop splits a CSS value on commas outside parentheses.
func splitTop(v string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range v {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, v[start:i])
				start = i + 1
			}
		}
	}
	return append(out, v[start:])
}

// blankComments replaces each comment between open and close with spaces,
// keeping newlines so offsets and line numbers stay valid.
func blankComments(src, open, closer string) string {
	b := []byte(src)
	for i := 0; i < len(b); {
		j := strings.Index(string(b[i:]), open)
		if j < 0 {
			break
		}
		j += i
		k := strings.Index(string(b[j+len(open):]), closer)
		end := len(b)
		if k >= 0 {
			end = j + len(open) + k + len(closer)
		}
		for x := j; x < end; x++ {
			if b[x] != '\n' {
				b[x] = ' '
			}
		}
		i = end
	}
	return string(b)
}

// Line numbers -------------------------------------------------------------

type lineIdx []int

func lineIndex(src string) lineIdx {
	idx := lineIdx{0}
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

func (l lineIdx) line(off int) int {
	return sort.Search(len(l), func(i int) bool { return l[i] > off })
}

// Extraction ---------------------------------------------------------------

// UIString is one extracted string and the line it starts on.
type UIString struct {
	Line int
	Text string
}

// nonUIAttrs are JSX and HTML attributes whose values are never shown to a
// person: class names, references, identifiers, SVG geometry. Values of every
// other attribute (title, aria-label, placeholder, alt, label and component
// props) are UI strings.
var nonUIAttrs = map[string]bool{
	"classname": true, "class": true, "href": true, "src": true, "srcset": true, "id": true, "key": true,
	"type": true, "role": true, "rel": true, "target": true, "style": true, "htmlfor": true, "for": true,
	"name": true, "d": true, "viewbox": true, "fill": true, "stroke": true, "points": true, "transform": true,
	"x": true, "y": true, "x1": true, "x2": true, "y1": true, "y2": true, "cx": true, "cy": true, "r": true,
	"rx": true, "ry": true, "width": true, "height": true, "method": true, "action": true, "lang": true,
	"dir": true, "xmlns": true, "path": true, "to": true, "ref": true, "autocomplete": true, "inputmode": true,
	"pattern": true, "accept": true, "form": true, "media": true, "sizes": true, "as": true, "crossorigin": true,
	"integrity": true, "charset": true, "aria-controls": true, "aria-describedby": true, "aria-labelledby": true,
	"aria-owns": true, "aria-current": true, "aria-hidden": true, "aria-live": true, "aria-haspopup": true,
	"aria-expanded": true, "aria-selected": true, "aria-pressed": true, "aria-checked": true, "aria-sort": true,
	"aria-level": true, "aria-modal": true, "aria-orientation": true, "aria-autocomplete": true,
	"strokewidth": true, "stroke-width": true, "strokelinejoin": true, "strokelinecap": true, "strokedasharray": true,
	"textanchor": true, "text-anchor": true, "dominantbaseline": true, "preserveaspectratio": true,
	"markerend": true, "marker-end": true, "clippath": true, "mask": true, "filter": true, "focusable": true,
	"tabindex": true, "scope": true, "colspan": true, "rowspan": true, "headers": true, "datetime": true,
	"loading": true, "decoding": true, "fetchpriority": true, "referrerpolicy": true, "sandbox": true,
	"allow": true, "download": true, "hreflang": true, "enctype": true, "spellcheck": true, "wrap": true,
	"dangerouslysetinnerhtml": true,
}

func nonUIAttr(name string) bool {
	n := strings.ToLower(name)
	return nonUIAttrs[n] || strings.HasPrefix(n, "data-")
}

var (
	urlRe      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:(//)?\S*$`)
	codeLikeRe = regexp.MustCompile(`^[a-z0-9_\-./:#@?&=%+*,;()\[\]{}<>|^$\\~!'"]*$`)
	identRe    = regexp.MustCompile(`^[a-z0-9]+$`)
)

// codeLike reports whether a string literal is an identifier, path, class
// list, selector or URL rather than text for a person: no white space, no
// capital letter, and at least one punctuation character; or a URL.
func codeLike(s string) bool {
	if s == "" || urlRe.MatchString(s) && !strings.ContainsAny(s, " \t\n") {
		return true
	}
	if strings.ContainsAny(s, " \t\n") {
		return false
	}
	return codeLikeRe.MatchString(s) && !identRe.MatchString(s)
}

// jsScanner is a small tokenizer for TypeScript and JavaScript with optional
// JSX. It does not build a syntax tree; it tells strings, template literals,
// regular expressions, comments and JSX text apart well enough to extract the
// text a person reads.
type jsScanner struct {
	src   string
	i     int
	jsx   bool
	lines lineIdx
	out   []UIString
	skip  int      // >0 while inside a non-UI JSX attribute expression
	prev  string   // previous significant token
	hist  []string // last few significant tokens
}

func extractJS(src string, jsx bool) []UIString {
	s := &jsScanner{src: src, jsx: jsx, lines: lineIndex(src)}
	s.code(false)
	return s.out
}

func (s *jsScanner) emit(off int, text string) {
	if s.skip > 0 {
		return
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	s.out = append(s.out, UIString{Line: s.lines.line(off), Text: text})
}

func (s *jsScanner) tok(t string) {
	s.prev = t
	s.hist = append(s.hist, t)
	if len(s.hist) > 4 {
		s.hist = s.hist[1:]
	}
}

// importContext reports whether a string here is a module specifier.
func (s *jsScanner) importContext() bool {
	n := len(s.hist)
	if n >= 1 && (s.hist[n-1] == "from" || s.hist[n-1] == "import") {
		return true
	}
	if n >= 2 && s.hist[n-1] == "(" && (s.hist[n-2] == "require" || s.hist[n-2] == "import") {
		return true
	}
	return false
}

// regexOK reports whether a "/" here starts a regular expression literal.
func (s *jsScanner) regexOK() bool {
	switch s.prev {
	case "", "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "&&", "||", "=>", "return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "+", "-", "*", "%", "<", ">", "~", "^", "==", "!=":
		return true
	}
	return false
}

// jsxOK reports whether a "<" here opens a JSX element.
func (s *jsScanner) jsxOK() bool {
	if !s.jsx {
		return false
	}
	switch s.prev {
	case "", "(", ",", "=", ":", "[", "?", "{", "}", ";", "&&", "||", "=>", "return", "jsx", "default", "??":
		return true
	}
	return false
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentChar(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

func (s *jsScanner) peek(k int) byte {
	if s.i+k < len(s.src) {
		return s.src[s.i+k]
	}
	return 0
}

// code scans code until the end of input or, when inBrace, until the "}"
// that closes the expression the caller opened.
func (s *jsScanner) code(inBrace bool) {
	depth := 0
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			s.i++
		case c == '/' && s.peek(1) == '/':
			for s.i < len(s.src) && s.src[s.i] != '\n' {
				s.i++
			}
		case c == '/' && s.peek(1) == '*':
			end := strings.Index(s.src[s.i+2:], "*/")
			if end < 0 {
				s.i = len(s.src)
			} else {
				s.i += end + 4
			}
		case c == '"' || c == '\'':
			start := s.i
			text := s.quoted(c)
			if !s.importContext() && !codeLike(text) {
				s.emit(start, text)
			}
			s.tok("str")
		case c == '`':
			tagged := s.prev != "" && (isIdentChar(s.prev[len(s.prev)-1]) && !keywordLike(s.prev))
			if tagged {
				s.skip++
			}
			s.template()
			if tagged {
				s.skip--
			}
			s.tok("str")
		case c == '/' && s.regexOK():
			s.regex()
			s.tok("re")
		case c == '{':
			depth++
			s.i++
			s.tok("{")
		case c == '}':
			if depth == 0 && inBrace {
				s.i++
				return
			}
			depth--
			s.i++
			s.tok("}")
		case c == '<' && s.jsxOK() && (isIdentStart(s.peek(1)) || s.peek(1) == '>') && !s.typeParams():
			s.element()
			s.tok("jsx")
		case isIdentStart(c):
			j := s.i
			for j < len(s.src) && isIdentChar(s.src[j]) {
				j++
			}
			s.tok(s.src[s.i:j])
			s.i = j
		case c >= '0' && c <= '9':
			j := s.i
			for j < len(s.src) && (isIdentChar(s.src[j]) || s.src[j] == '.') {
				j++
			}
			s.tok("num")
			s.i = j
		default:
			two := ""
			if s.i+1 < len(s.src) {
				two = s.src[s.i : s.i+2]
			}
			switch two {
			case "=>", "&&", "||", "??", "==", "!=":
				s.tok(two)
				s.i += 2
			default:
				s.tok(string(c))
				s.i++
			}
		}
	}
}

// typeParams reports whether the "<" at s.i opens the type parameters of a
// generic arrow function (<T,>(x: T) => ..., <T extends U>(...)) rather than a
// JSX element.
func (s *jsScanner) typeParams() bool {
	j := s.i + 1
	for j < len(s.src) && isIdentChar(s.src[j]) {
		j++
	}
	for j < len(s.src) && (s.src[j] == ' ' || s.src[j] == '\t') {
		j++
	}
	rest := s.src[j:]
	return strings.HasPrefix(rest, ",") || strings.HasPrefix(rest, "extends ")
}

func keywordLike(w string) bool {
	switch w {
	case "return", "typeof", "case", "in", "of", "new", "void", "throw", "await", "yield", "default", "else", "do":
		return true
	}
	return false
}

// quoted reads a '...' or "..." literal at s.i and returns its decoded text.
func (s *jsScanner) quoted(q byte) string {
	s.i++
	var b strings.Builder
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == q:
			s.i++
			return b.String()
		case c == '\\':
			s.escape(&b)
		case c == '\n':
			return b.String() // unterminated; do not run away
		default:
			b.WriteByte(c)
			s.i++
		}
	}
	return b.String()
}

// escape decodes one escape sequence at s.i into b.
func (s *jsScanner) escape(b *strings.Builder) {
	s.i++ // backslash
	if s.i >= len(s.src) {
		return
	}
	c := s.src[s.i]
	s.i++
	switch c {
	case 'n', 'r', 't':
		b.WriteByte(' ')
	case 'u':
		if s.i < len(s.src) && s.src[s.i] == '{' {
			end := strings.IndexByte(s.src[s.i:], '}')
			if end > 0 {
				if r, ok := hexRune(s.src[s.i+1 : s.i+end]); ok {
					b.WriteRune(r)
				}
				s.i += end + 1
			}
			return
		}
		if s.i+4 <= len(s.src) {
			if r, ok := hexRune(s.src[s.i : s.i+4]); ok {
				b.WriteRune(r)
				s.i += 4
			}
		}
	case 'x':
		if s.i+2 <= len(s.src) {
			if r, ok := hexRune(s.src[s.i : s.i+2]); ok {
				b.WriteRune(r)
				s.i += 2
			}
		}
	case '\n':
	default:
		b.WriteByte(c)
	}
}

// hexRune decodes 1 to 6 hexadecimal digits as a code point.
func hexRune(h string) (rune, bool) {
	if len(h) == 0 || len(h) > 6 {
		return 0, false
	}
	var r rune
	for _, c := range h {
		switch {
		case c >= '0' && c <= '9':
			r = r*16 + c - '0'
		case c >= 'a' && c <= 'f':
			r = r*16 + c - 'a' + 10
		case c >= 'A' && c <= 'F':
			r = r*16 + c - 'A' + 10
		default:
			return 0, false
		}
	}
	return r, r <= unicode.MaxRune
}

// template reads a template literal at s.i. The text parts, joined with "{}"
// in place of each expression, are one UI string; expressions are scanned as
// code.
func (s *jsScanner) template() {
	start := s.i
	s.i++
	var b strings.Builder
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '`':
			s.i++
			if t := b.String(); !codeLike(strings.TrimSpace(t)) {
				s.emit(start, t)
			}
			return
		case c == '\\':
			s.escape(&b)
		case c == '$' && s.peek(1) == '{':
			s.i += 2
			saved, savedHist := s.prev, s.hist
			s.prev, s.hist = "", nil
			s.code(true)
			s.prev, s.hist = saved, savedHist
			b.WriteString("{}")
		default:
			b.WriteByte(c)
			s.i++
		}
	}
}

// regex skips a regular expression literal at s.i.
func (s *jsScanner) regex() {
	s.i++
	inClass := false
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '\\':
			s.i += 2
			continue
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			s.i++
			for s.i < len(s.src) && isIdentChar(s.src[s.i]) {
				s.i++
			}
			return
		case c == '\n':
			return
		}
		s.i++
	}
}

func (s *jsScanner) skipSpace() {
	for s.i < len(s.src) && strings.IndexByte(" \t\r\n", s.src[s.i]) >= 0 {
		s.i++
	}
}

// expr scans a {...} JSX expression at s.i, with skip when its value is not
// a UI string.
func (s *jsScanner) expr(skip bool) {
	s.i++ // {
	if skip {
		s.skip++
	}
	saved, savedHist := s.prev, s.hist
	s.prev, s.hist = "", nil
	s.code(true)
	s.prev, s.hist = saved, savedHist
	if skip {
		s.skip--
	}
}

// element reads a JSX element at s.i ("<"), including its children.
func (s *jsScanner) element() {
	s.i++ // <
	if s.peek(0) == '>' {
		s.i++
		s.children()
		return
	}
	for s.i < len(s.src) && (isIdentChar(s.src[s.i]) || strings.IndexByte(".:-", s.src[s.i]) >= 0) {
		s.i++
	}
	for s.i < len(s.src) {
		s.skipSpace()
		if s.i >= len(s.src) {
			return
		}
		c := s.src[s.i]
		switch {
		case c == '/' && s.peek(1) == '>':
			s.i += 2
			return
		case c == '>':
			s.i++
			s.children()
			return
		case c == '{':
			s.expr(false) // spread attributes
		case c == '<': // type arguments on a component: skip to the matching '>'
			for s.i < len(s.src) && s.src[s.i] != '>' {
				s.i++
			}
			s.i++
		default:
			j := s.i
			for j < len(s.src) && (isIdentChar(s.src[j]) || strings.IndexByte("-:", s.src[j]) >= 0) {
				j++
			}
			if j == s.i {
				s.i++ // unexpected character; move on
				continue
			}
			name := s.src[s.i:j]
			s.i = j
			s.skipSpace()
			if s.peek(0) != '=' {
				continue
			}
			s.i++
			s.skipSpace()
			switch q := s.peek(0); q {
			case '"', '\'':
				start := s.i
				end := strings.IndexByte(s.src[s.i+1:], q)
				if end < 0 {
					s.i = len(s.src)
					return
				}
				text := html.UnescapeString(s.src[s.i+1 : s.i+1+end])
				s.i += end + 2
				if !nonUIAttr(name) && !codeLike(text) {
					s.emit(start, text)
				}
			case '{':
				s.expr(nonUIAttr(name))
			}
		}
	}
}

// children reads JSX children up to and including the closing tag.
func (s *jsScanner) children() {
	for s.i < len(s.src) {
		start := s.i
		for s.i < len(s.src) && s.src[s.i] != '<' && s.src[s.i] != '{' {
			s.i++
		}
		if raw := s.src[start:s.i]; strings.TrimSpace(raw) != "" {
			lead := len(raw) - len(strings.TrimLeft(raw, " \t\r\n"))
			s.emit(start+lead, strings.Join(strings.Fields(html.UnescapeString(raw)), " "))
		}
		if s.i >= len(s.src) {
			return
		}
		if s.src[s.i] == '{' {
			s.expr(false)
			continue
		}
		if s.peek(1) == '/' {
			end := strings.IndexByte(s.src[s.i:], '>')
			if end < 0 {
				s.i = len(s.src)
			} else {
				s.i += end + 1
			}
			return
		}
		s.element()
	}
}

// HTML ---------------------------------------------------------------------

var (
	htmlBlockRe = regexp.MustCompile(`(?is)<!--.*?-->|<script\b.*?</script\s*>|<style\b.*?</style\s*>`)
	htmlTagRe   = regexp.MustCompile(`(?s)<[^>]*>`)
	htmlAttrRe  = regexp.MustCompile(`(?is)([a-z][a-z0-9:_-]*)\s*=\s*("([^"]*)"|'([^']*)')`)
	htmlMetaUI  = regexp.MustCompile(`(?i)(name\s*=\s*["']?(description|application-name)|property\s*=\s*["']?og:(title|description))`)
)

// extractHTML returns the text nodes and user-facing attribute values of an
// HTML page; scripts, styles and comments are left out.
func extractHTML(src string) []UIString {
	src = htmlBlockRe.ReplaceAllStringFunc(src, func(m string) string {
		return strings.Map(func(r rune) rune {
			if r == '\n' {
				return r
			}
			return ' '
		}, m)
	})
	lines := lineIndex(src)
	var out []UIString
	add := func(off int, text string) {
		text = strings.Join(strings.Fields(html.UnescapeString(text)), " ")
		if text != "" {
			out = append(out, UIString{Line: lines.line(off), Text: text})
		}
	}
	last := 0
	for _, t := range htmlTagRe.FindAllStringIndex(src, -1) {
		if raw := src[last:t[0]]; strings.TrimSpace(raw) != "" {
			add(last+len(raw)-len(strings.TrimLeft(raw, " \t\r\n")), raw)
		}
		tag := src[t[0]:t[1]]
		for _, a := range htmlAttrRe.FindAllStringSubmatchIndex(tag, -1) {
			name := strings.ToLower(tag[a[2]:a[3]])
			vs, ve := a[6], a[7]
			if vs < 0 {
				vs, ve = a[8], a[9]
			}
			val := tag[vs:ve]
			if nonUIAttr(name) || codeLike(val) {
				continue
			}
			if name == "content" && !htmlMetaUI.MatchString(tag) {
				continue
			}
			add(t[0]+vs, val)
		}
		last = t[1]
	}
	if raw := src[last:]; strings.TrimSpace(raw) != "" {
		add(last, raw)
	}
	return out
}

// Rust ---------------------------------------------------------------------

// extractRust returns the string literals of a Rust source file (window
// titles, tray labels, notification text), without comments.
func extractRust(src string) []UIString {
	lines := lineIndex(src)
	var out []UIString
	add := func(off int, text string) {
		text = strings.TrimSpace(text)
		if text != "" && !codeLike(text) {
			out = append(out, UIString{Line: lines.line(off), Text: text})
		}
	}
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case strings.HasPrefix(src[i:], "//"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out
			}
			i += end + 4
		case c == 'r' && (strings.HasPrefix(src[i:], `r"`) || strings.HasPrefix(src[i:], `r#`)) && (i == 0 || !isIdentChar(src[i-1])):
			j := i + 1
			hashes := 0
			for j < len(src) && src[j] == '#' {
				hashes++
				j++
			}
			if j >= len(src) || src[j] != '"' {
				i = j
				continue
			}
			closer := `"` + strings.Repeat("#", hashes)
			end := strings.Index(src[j+1:], closer)
			if end < 0 {
				return out
			}
			add(i, src[j+1:j+1+end])
			i = j + 1 + end + len(closer)
		case c == '"':
			start := i
			i++
			var b strings.Builder
			for i < len(src) && src[i] != '"' {
				if src[i] == '\\' && i+1 < len(src) {
					switch src[i+1] {
					case 'n', 't', 'r':
						b.WriteByte(' ')
					case 'u':
						if end := strings.IndexByte(src[i:], '}'); end > 0 && i+2 < len(src) && src[i+2] == '{' {
							if r, ok := hexRune(src[i+3 : i+end]); ok {
								b.WriteRune(r)
							}
							i += end + 1
							continue
						}
					default:
						b.WriteByte(src[i+1])
					}
					i += 2
					continue
				}
				b.WriteByte(src[i])
				i++
			}
			i++
			add(start, b.String())
		case c == '\'':
			// A char literal ('a', '\n', '\u{2014}') or a lifetime ('a).
			if i+2 < len(src) && src[i+1] != '\\' {
				_, size := utf8.DecodeRuneInString(src[i+1:])
				if i+1+size < len(src) && src[i+1+size] == '\'' {
					i += 2 + size
					continue
				}
			} else if i+1 < len(src) && src[i+1] == '\\' {
				if end := strings.IndexByte(src[i+2:], '\''); end >= 0 {
					i += end + 3
					continue
				}
			}
			i++
		default:
			i++
		}
	}
	return out
}

// JSON ---------------------------------------------------------------------

// extractJSON returns every string value (not object keys) of a JSON
// document such as the shared message catalogue. A document that does not
// parse yields what was read before the error; its own tests catch that.
func extractJSON(src string) []UIString {
	lines := lineIndex(src)
	dec := json.NewDecoder(strings.NewReader(src))
	var out []UIString
	// One frame per open container: whether it is an object and whether
	// the next string in it is a key.
	type frame struct{ object, key bool }
	var stack []frame
	for {
		off := int(dec.InputOffset())
		t, err := dec.Token()
		if err != nil {
			return out
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, frame{object: true, key: true})
			case '[':
				stack = append(stack, frame{})
			default:
				stack = stack[:len(stack)-1]
				if n := len(stack); n > 0 && stack[n-1].object {
					stack[n-1].key = true
				}
			}
			continue
		case string:
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].key {
				stack[n-1].key = false
				continue
			}
			if text := strings.TrimSpace(v); text != "" {
				// The token starts after any separator and white space.
				for off < len(src) && strings.IndexByte(" \t\r\n,:", src[off]) >= 0 {
					off++
				}
				out = append(out, UIString{Line: lines.line(off), Text: text})
			}
		}
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].key = true
		}
	}
}

// Allowlist ----------------------------------------------------------------

// AllowEntry is one line of the allowlist: every finding of Rule in Path whose
// matched text equals Match (ignoring case) is accepted for Reason.
type AllowEntry struct {
	Line   int
	Path   string
	Rule   string
	Match  string
	Reason string
}

// Rules lists the rule names an allowlist entry may name.
var Rules = map[string]bool{
	"banned-word": true, "exclamation": true, "emoji": true, "em-dash": true,
	"css-gradient": true, "css-backdrop-filter": true, "css-text-shadow": true, "css-box-shadow": true,
	"css-filter": true, "css-radius": true, "css-animation": true,
}

// parseAllowlist reads the allowlist format of docs/design/writing.md:
//
//	path rule match text  # reason
//
// Blank lines and lines starting with "#" are comments. The path and rule are
// the first two fields; the match is the rest of the line before " # ",
// trimmed; the reason after it is required.
func parseAllowlist(src string) ([]AllowEntry, error) {
	var out []AllowEntry
	sc := bufio.NewScanner(strings.NewReader(src))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		body, reason, ok := strings.Cut(line, " # ")
		if !ok {
			body, reason, ok = strings.Cut(line, "\t# ")
		}
		reason = strings.TrimSpace(reason)
		if !ok || reason == "" {
			return nil, fmt.Errorf("line %d: no reason (write \"  # reason\" after the entry)", n)
		}
		f := strings.Fields(body)
		if len(f) < 3 {
			return nil, fmt.Errorf("line %d: want \"path rule match  # reason\"", n)
		}
		if !Rules[f[1]] {
			return nil, fmt.Errorf("line %d: unknown rule %q", n, f[1])
		}
		match := strings.TrimSpace(body)
		match = strings.TrimSpace(strings.TrimPrefix(match, f[0]))
		match = strings.TrimSpace(strings.TrimPrefix(match, f[1]))
		out = append(out, AllowEntry{Line: n, Path: f[0], Rule: f[1], Match: strings.Join(strings.Fields(match), " "), Reason: reason})
	}
	return out, sc.Err()
}

// applyAllowlist removes the allowed findings and returns the rest and the
// entries that matched no finding.
func applyAllowlist(findings []Finding, entries []AllowEntry) (rest []Finding, stale []AllowEntry) {
	used := make([]bool, len(entries))
	for _, f := range findings {
		allowed := false
		for i, e := range entries {
			if e.Path == f.Path && e.Rule == f.Rule && strings.EqualFold(e.Match, strings.Join(strings.Fields(f.Match), " ")) {
				used[i] = true
				allowed = true
			}
		}
		if !allowed {
			rest = append(rest, f)
		}
	}
	for i, e := range entries {
		if !used[i] {
			stale = append(stale, e)
		}
	}
	return rest, stale
}
