package southbound

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEncodeValue: the examples of the specification's Value Encoding
// table, plus a tab, an empty value and a sentinel prefix without suffix.
func TestEncodeValue(t *testing.T) {
	for in, want := range map[string]string{
		"us-west1":           "us-west1",
		"Hello, 世界":          "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":           "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":       "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
		"a\tb":               "a\tb",
		"\ttab":              "=?base64?CXRhYg==?=",
		"":                   "",
		"=?base64?open":      "=?base64?open",
		"del\x7f":            "=?base64?ZGVsfw==?=",
	} {
		if got := EncodeValue(in); got != want {
			t.Errorf("EncodeValue(%q) = %q, want %q", in, got, want)
		}
		if dec, ok := DecodeValue(EncodeValue(in)); !ok || dec != in {
			t.Errorf("round trip of %q gave %q", in, dec)
		}
	}
}

func TestHeaderParams(t *testing.T) {
	schema := `{"type":"object","properties":{
		"region":{"type":"string","x-mcp-header":"Region"},
		"n":{"type":"integer","x-mcp-header":"Count"},
		"flag":{"type":"boolean","x-mcp-header":"Flag"},
		"opts":{"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"Tenant"}}},
		"plain":{"type":"string"}}}`
	ps, ok := headerParams(json.RawMessage(schema))
	if !ok || len(ps) != 4 {
		t.Fatalf("params %+v ok %v", ps, ok)
	}
	h := http.Header{}
	setParamHeaders(h, ps, json.RawMessage(`{"region":"Zürich","n":42,"flag":false,"opts":{"tenant":" t "},"plain":"x"}`))
	want := map[string]string{
		"Mcp-Param-Region": "=?base64?WsO8cmljaA==?=",
		"Mcp-Param-Count":  "42",
		"Mcp-Param-Flag":   "false",
		"Mcp-Param-Tenant": "=?base64?IHQg?=",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if len(h) != len(want) {
		t.Errorf("headers %v", h)
	}
	// Absent and null values, a float and an unsafe integer: no header.
	h = http.Header{}
	setParamHeaders(h, ps, json.RawMessage(`{"region":null,"n":1.5,"opts":{}}`))
	h2 := http.Header{}
	setParamHeaders(h2, ps, json.RawMessage(`{"n":9007199254740993}`))
	if len(h) != 0 || len(h2) != 0 {
		t.Errorf("headers %v %v", h, h2)
	}
	h = http.Header{}
	setParamHeaders(h, ps, json.RawMessage(`{"n":7.0}`))
	if h.Get("Mcp-Param-Count") != "7" {
		t.Errorf("integral float: %v", h)
	}
	for _, bad := range []string{
		`{"properties":{"a":{"type":"number","x-mcp-header":"A"}}}`,
		`{"properties":{"a":{"type":"string","x-mcp-header":"A B"}}}`,
		`{"properties":{"a":{"type":"string","x-mcp-header":""}}}`,
		`{"properties":{"a":{"type":"string","x-mcp-header":"X"},"b":{"type":"string","x-mcp-header":"x"}}}`,
		`{"properties":{"a":{"type":"string","x-mcp-header":7}}}`,
	} {
		if _, ok := headerParams(json.RawMessage(bad)); ok {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TestSSEReader: comment lines in every position, CR LF and CR line ends,
// multi-line data, an event without data, unknown fields and an oversized
// event (FR-5.30).
func TestSSEReader(t *testing.T) {
	stream := ":\r\n: keep-alive\r\nid: 1\r\ndata: {\"a\":1}\r\n\r\n" +
		":comment between\n\nid: 2\nfoo: bar\ndata: line1\n: inside an event\ndata: line2\n\n" +
		"id: 3\r\r" + // an event with only an id
		"retry: 250\rdata: cr\r\r" +
		"data: " + strings.Repeat("x", 100) + "\n\n" +
		"data: after\n\n" +
		"data: unterminated"
	rd := newSSEReader(strings.NewReader(stream), 64)
	var got []event
	for {
		ev, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	if len(got) != 6 {
		t.Fatalf("%d events: %+v", len(got), got)
	}
	if got[0].ID != "1" || string(got[0].Data) != `{"a":1}` ||
		got[1].ID != "2" || string(got[1].Data) != "line1\nline2" ||
		got[2].ID != "3" || got[2].Data != nil ||
		string(got[3].Data) != "cr" || got[3].Retry.Milliseconds() != 250 ||
		!got[4].Oversized || len(got[4].Data) != 64 ||
		string(got[5].Data) != "after" || got[5].Oversized {
		t.Fatalf("events %+v", got)
	}
	if rd.Comments != 4 {
		t.Fatalf("comments %d", rd.Comments)
	}
}

func TestCheckURL(t *testing.T) {
	for _, ok := range []string{"https://mcp.example.com/mcp", "http://127.0.0.1:4444/servers/x/mcp", "http://localhost:9/mcp", "http://[::1]:9/mcp"} {
		if _, err := CheckURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.com/mcp", "http://10.0.0.1/mcp", "https://u:p@example.com/mcp", "https://example.com/mcp#x", "ftp://example.com/", "https:///mcp", "file:///etc/passwd"} {
		if _, err := CheckURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestTokenFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if tok, err := TokenFromEnv(env(nil)); err != nil || tok != "" {
		t.Fatalf("none: %q %v", tok, err)
	}
	if tok, err := TokenFromEnv(env(map[string]string{TokenEnv: " abc \n"})); err != nil || tok != "abc" {
		t.Fatalf("env: %q %v", tok, err)
	}
	f := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(f, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, err := TokenFromEnv(env(map[string]string{TokenFileEnv: f})); err != nil || tok != "from-file" {
		t.Fatalf("file: %q %v", tok, err)
	}
	if _, err := TokenFromEnv(env(map[string]string{TokenEnv: "a", TokenFileEnv: f})); err == nil {
		t.Fatal("both accepted")
	}
	_, err := TokenFromEnv(env(map[string]string{TokenEnv: "a\r\nX-Injected: 1"}))
	if err == nil || strings.Contains(err.Error(), "Injected") {
		t.Fatalf("header injection: %v", err)
	}
}
