package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Feature extraction for the request-shape (P-024 to P-044) and
// response-shape (P-120 to P-127) parameters. Each function follows the
// derivation column of docs/parameters.json; deviations are listed in
// docs/observation.md.

// Entropy is the Shannon entropy in bits per character over the UTF-8 code
// points of s (P-028, P-123). The empty string has entropy 0.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// unicodeControl counts control and format characters other than tab,
// newline and carriage return (P-044): C0/C1 controls, bidirectional
// overrides, zero-width characters and other Cf code points.
func unicodeControl(s string) int {
	n := 0
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			n++
		}
	}
	return n
}

// looksLikePath reports a string leaf that is an absolute, home-relative
// or dot-relative filesystem path.
func looksLikePath(s string) bool {
	if len(s) > 4096 || strings.ContainsAny(s, "\n\x00") {
		return false
	}
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		(len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') && unicode.IsLetter(rune(s[0])))
}

// looksLikeURL reports a string leaf that parses as an absolute URL with a
// scheme and a host.
func looksLikeURL(s string) bool {
	if len(s) > 8192 || !strings.Contains(s, "://") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

type walkStats struct {
	maxDepth int
	strLens  []int
	text     strings.Builder
	paths    int
	urls     int
	controls int
	fields   int
}

func (w *walkStats) walk(v any, depth int) {
	if depth > w.maxDepth {
		w.maxDepth = depth
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.fields++
			w.controls += unicodeControl(k)
			w.walk(x[k], depth+1)
		}
	case []any:
		for _, e := range x {
			w.walk(e, depth+1)
		}
	case string:
		w.strLens = append(w.strLens, utf8.RuneCountInString(x))
		if w.text.Len() < 1<<20 {
			w.text.WriteString(x)
		}
		if looksLikePath(x) {
			w.paths++
		}
		if looksLikeURL(x) {
			w.urls++
		}
		w.controls += unicodeControl(x)
	}
}

// ArgumentFeatures computes the request-shape parameters from the tool-call
// arguments as received (a JSON object or null).
//
//   - request_bytes (P-024): length of the arguments JSON.
//   - argument_count (P-025): number of top-level arguments.
//   - argument_max_depth (P-026): nesting depth; the arguments object is
//     depth 1, a scalar inside it depth 1, an object inside it depth 2.
//   - argument_string_lengths (P-027): code-point length of each string
//     leaf, in document order of a sorted-key walk.
//   - argument_entropy (P-028): entropy of the concatenated string leaves.
//   - path_argument_count, url_argument_count (P-029, P-030): string
//     leaves that look like paths or absolute URLs.
//   - argument_value_hashes (P-040): sha256 of each top-level argument's
//     canonical JSON, by argument name (S2).
//   - unicode_control_count (P-044).
//
// It also returns the digest of the whole canonical argument object, used
// for repeated_identical_calls (P-066).
func ArgumentFeatures(args json.RawMessage) (map[string]any, string) {
	out := map[string]any{"request_bytes": int64(len(args))}
	var obj map[string]any
	if len(args) > 0 && string(args) != "null" {
		if err := json.Unmarshal(args, &obj); err != nil {
			out["argument_count"] = int64(0)
			return out, ""
		}
	}
	canon, _ := json.Marshal(obj) // encoding/json sorts map keys: canonical enough for a digest
	sum := sha256.Sum256(canon)
	digest := hex.EncodeToString(sum[:])
	w := &walkStats{}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	hashes := map[string]string{}
	for _, k := range keys {
		w.controls += unicodeControl(k)
		w.walk(obj[k], 1)
		raw, _ := json.Marshal(obj[k])
		h := sha256.Sum256(raw)
		hashes[k] = hex.EncodeToString(h[:])
	}
	if len(obj) > 0 && w.maxDepth < 1 {
		w.maxDepth = 1
	}
	lens := make([]int64, len(w.strLens))
	for i, l := range w.strLens {
		lens[i] = int64(l)
	}
	out["argument_count"] = int64(len(obj))
	out["argument_max_depth"] = int64(w.maxDepth)
	out["argument_string_lengths"] = lens
	out["argument_entropy"] = Entropy(w.text.String())
	out["path_argument_count"] = int64(w.paths)
	out["url_argument_count"] = int64(w.urls)
	out["argument_value_hashes"] = hashes
	out["unicode_control_count"] = int64(w.controls)
	return out, digest
}

// ResponseFeatures computes the response-shape parameters from a tool
// result.
//
//   - response_bytes (P-120): length of the result's JSON encoding.
//   - content_parts_by_type (P-121): count of content parts per type.
//   - output_schema_conformance (P-122): "conforms", "violates" or
//     "no_schema" (validator supplied by the caller).
//   - response_entropy (P-123): entropy of the text parts.
//   - response_token_estimate (P-124): text characters divided by 4.
//   - is_error (P-125): {"is_error": bool}.
//   - structured_field_count (P-126): recursive field count of
//     structuredContent.
//   - embedded_url_count (P-127): resource links, embedded resources and
//     absolute URLs in text.
func ResponseFeatures(res *mcp.CallToolResult, validate func(structured any) string, hasSchema bool) map[string]any {
	out := map[string]any{}
	if res == nil {
		return out
	}
	raw, err := json.Marshal(res)
	if err == nil {
		out["response_bytes"] = int64(len(raw))
	}
	parts := map[string]int64{}
	var text strings.Builder
	urls := 0
	for _, c := range res.Content {
		switch x := c.(type) {
		case *mcp.TextContent:
			parts["text"]++
			if text.Len() < 4<<20 {
				text.WriteString(x.Text)
			}
			for _, f := range strings.Fields(x.Text) {
				if looksLikeURL(strings.Trim(f, `"'()<>[],.`)) {
					urls++
				}
			}
		case *mcp.ImageContent:
			parts["image"]++
		case *mcp.AudioContent:
			parts["audio"]++
		case *mcp.ResourceLink:
			parts["resource_link"]++
			urls++
		case *mcp.EmbeddedResource:
			parts["resource"]++
			urls++
		default:
			parts["other"]++
		}
	}
	out["content_parts_by_type"] = parts
	t := text.String()
	out["response_entropy"] = Entropy(t)
	out["response_token_estimate"] = int64(utf8.RuneCountInString(t) / 4)
	out["is_error"] = map[string]any{"is_error": res.IsError}
	if res.StructuredContent != nil {
		var v any
		if b, err := json.Marshal(res.StructuredContent); err == nil && json.Unmarshal(b, &v) == nil {
			w := &walkStats{}
			w.walk(v, 0)
			out["structured_field_count"] = int64(w.fields)
		}
	} else {
		out["structured_field_count"] = int64(0)
	}
	switch {
	case !hasSchema:
		out["output_schema_conformance"] = "no_schema"
	case res.StructuredContent == nil:
		out["output_schema_conformance"] = "violates"
	case validate != nil && validate(res.StructuredContent) != "":
		out["output_schema_conformance"] = "violates"
	default:
		out["output_schema_conformance"] = "conforms"
	}
	out["embedded_url_count"] = int64(urls)
	return out
}
