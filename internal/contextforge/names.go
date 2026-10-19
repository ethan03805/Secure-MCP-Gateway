package contextforge

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Manifest tool names allow [A-Za-z0-9_]{1,47} (Appendix J).
const (
	maxToolName = 47
	hashedStem  = 38
)

var manifestToolName = regexp.MustCompile(`^[A-Za-z0-9_]{1,47}$`)

// ToolName pairs a hosted tool's manifest name with the name ContextForge
// serves it under (FR-22.10).
type ToolName struct {
	Name        string `json:"name"`
	BackendName string `json:"backend_name"`
}

// GatewayName is the ContextForge gateway name, and slug, used for the
// hosted package of a catalog entry. It is fixed at the probe, recorded in
// the manifest's upstream member and reused at every registration
// (FR-22.10, FR-22.34). It only uses characters ContextForge's slug keeps,
// so the name and the slug are equal.
func GatewayName(entryID string) string {
	s := "smcp-" + serverID(entryID)
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	return s
}

// MapToolNames derives the manifest name of every tool a hosted package's
// gateway serves (FR-22.10): remove the "<slug>-" prefix, replace every
// character outside [A-Za-z0-9_] with "_", and, for a result longer than 47
// characters or equal to the result of another tool, use its first 38
// characters, "_" and the first 8 hexadecimal digits of the SHA-256 of the
// backend name. The result depends only on the names, not on their order.
// It refuses, with TOOL_NAME_COLLISION naming the tools, a backend name
// served twice, a name that maps to nothing, and two names that still map
// to the same manifest name.
func MapToolNames(slug string, backend []string) ([]ToolName, error) {
	first := make(map[string]string, len(backend))
	count := map[string]int{}
	seen := map[string]bool{}
	for _, b := range backend {
		if seen[b] {
			return nil, packaging.Errf(ReasonToolNameCollision, "the gateway serves tool %q twice", b)
		}
		seen[b] = true
		r := strings.TrimPrefix(b, slug+"-")
		r = sanitizeToolName(r)
		first[b] = r
		count[r]++
	}
	out := make([]ToolName, 0, len(backend))
	byName := map[string][]string{}
	for _, b := range backend {
		r := first[b]
		if r == "" {
			return nil, packaging.Errf(ReasonToolNameCollision, "tool %q has no name after the gateway prefix", b)
		}
		if len(r) > maxToolName || count[r] > 1 {
			stem := r
			if len(stem) > hashedStem {
				stem = stem[:hashedStem]
			}
			sum := sha256.Sum256([]byte(b))
			r = stem + "_" + hex.EncodeToString(sum[:])[:8]
		}
		byName[r] = append(byName[r], b)
		out = append(out, ToolName{Name: r, BackendName: b})
	}
	var clashes []string
	for name, bs := range byName {
		if len(bs) > 1 {
			sort.Strings(bs)
			clashes = append(clashes, name+" <- "+strings.Join(bs, ", "))
		}
	}
	if len(clashes) > 0 {
		sort.Strings(clashes)
		return nil, packaging.Errf(ReasonToolNameCollision, "tools map to the same manifest name: %s", strings.Join(clashes, "; "))
	}
	for _, t := range out {
		if !manifestToolName.MatchString(t.Name) {
			return nil, packaging.Errf(ReasonToolNameCollision, "tool %q maps to %q, which is not a manifest tool name", t.BackendName, t.Name)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func sanitizeToolName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
