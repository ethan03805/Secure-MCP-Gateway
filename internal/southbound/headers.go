package southbound

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// Request metadata headers of the Streamable HTTP transport (MCP
// basic/transports/streamable-http, Standard Request Headers and Custom
// Headers from Tool Parameters).
const (
	HeaderProtocolVersion = "Mcp-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
	HeaderSession         = "Mcp-Session-Id"
	HeaderParamPrefix     = "Mcp-Param-"
)

const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// EncodeValue returns v as an Mcp-Name or Mcp-Param-* header value (FR-5.29):
// unchanged when every byte is visible ASCII, space or horizontal tab, the
// value neither starts nor ends with white space and does not look like the
// Base64 sentinel; otherwise "=?base64?" + Base64 of the UTF-8 bytes + "?=".
func EncodeValue(v string) string {
	if plainSafe(v) {
		return v
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(v)) + sentinelSuffix
}

func plainSafe(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	if v != "" && (isWS(v[0]) || isWS(v[len(v)-1])) {
		return false
	}
	return !(strings.HasPrefix(v, sentinelPrefix) && strings.HasSuffix(v, sentinelSuffix))
}

func isWS(c byte) bool { return c == ' ' || c == '\t' }

// DecodeValue reverses EncodeValue; a malformed sentinel value is returned
// unchanged with ok false. Used by tests and fixtures.
func DecodeValue(v string) (string, bool) {
	if !strings.HasPrefix(v, sentinelPrefix) || !strings.HasSuffix(v, sentinelSuffix) || len(v) < len(sentinelPrefix)+len(sentinelSuffix) {
		return v, true
	}
	b, err := base64.StdEncoding.DecodeString(v[len(sentinelPrefix) : len(v)-len(sentinelSuffix)])
	if err != nil {
		return v, false
	}
	return string(b), true
}

// headerParam is one x-mcp-header annotation of a tool's input schema: the
// header name part and the chain of properties keys leading to it.
type headerParam struct {
	name string
	path []string
}

// headerParams returns the x-mcp-header annotations of an input schema that
// are statically reachable through properties keys. ok is false when an
// annotation is invalid (not a token, not unique, on a type other than
// string, integer or boolean); the Tool Dispatcher does not present such a
// tool (FR-5.22), and the transport mirrors none of its parameters.
func headerParams(schema json.RawMessage) (params []headerParam, ok bool) {
	var root map[string]any
	if len(schema) == 0 || json.Unmarshal(schema, &root) != nil {
		return nil, true
	}
	seen := map[string]bool{}
	ok = true
	var walk func(node map[string]any, path []string, depth int)
	walk = func(node map[string]any, path []string, depth int) {
		if !ok || depth > 32 {
			return
		}
		props, _ := node["properties"].(map[string]any)
		for key, v := range props {
			child, isObj := v.(map[string]any)
			if !isObj {
				continue
			}
			p := append(append([]string(nil), path...), key)
			if h, has := child["x-mcp-header"]; has {
				name, isStr := h.(string)
				typ, _ := child["type"].(string)
				lower := strings.ToLower(name)
				if !isStr || !validToken(name) || seen[lower] || (typ != "string" && typ != "integer" && typ != "boolean") {
					ok = false
					return
				}
				seen[lower] = true
				params = append(params, headerParam{name: name, path: p})
			}
			walk(child, p, depth+1)
		}
	}
	walk(root, nil, 0)
	if !ok {
		return nil, false
	}
	return params, true
}

// validToken reports whether s is an RFC 9110 token (1*tchar).
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// maxSafeInteger is 2^53-1, the bound of x-mcp-header integer values.
const maxSafeInteger = 1<<53 - 1

// paramValue returns the header text of the argument at path, or ok false
// when it is absent, null or not a string, boolean or safe integer.
func paramValue(args map[string]any, path []string) (string, bool) {
	var cur any = args
	for _, k := range path {
		m, isMap := cur.(map[string]any)
		if !isMap {
			return "", false
		}
		if cur, isMap = m[k]; !isMap {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case json.Number:
		if i, err := strconv.ParseInt(string(v), 10, 64); err == nil {
			if i > maxSafeInteger || i < -maxSafeInteger {
				return "", false
			}
			return strconv.FormatInt(i, 10), true
		}
		f, err := v.Float64()
		if err != nil || f != math.Trunc(f) || math.Abs(f) > maxSafeInteger {
			return "", false
		}
		return strconv.FormatInt(int64(f), 10), true
	}
	return "", false
}

// setParamHeaders mirrors the annotated arguments of a tools/call into
// Mcp-Param-* headers (FR-5.29).
func setParamHeaders(h http.Header, params []headerParam, rawArgs json.RawMessage) {
	if len(params) == 0 || len(rawArgs) == 0 {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(rawArgs))
	dec.UseNumber()
	var args map[string]any
	if dec.Decode(&args) != nil {
		return
	}
	for _, p := range params {
		if v, ok := paramValue(args, p.path); ok {
			h.Set(HeaderParamPrefix+p.name, EncodeValue(v))
		}
	}
}
