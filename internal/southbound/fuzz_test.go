package southbound

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Fuzz targets of the security review of v1.3.0
// (docs/security-review-v1.3.md). The seeds run with go test; a fuzzing
// run is go test -run '^$' -fuzz FuzzSSEReader ./internal/southbound.

// FuzzSSEReader: whatever a server sends, the event stream parser ends,
// never returns more event data than the bound, and keeps event IDs short
// and free of NUL, line breaks and carriage returns (they become the
// Last-Event-ID header of a resumption).
func FuzzSSEReader(f *testing.F) {
	// FR-5.28 and FR-5.30 in part (SSE responses, comments, the message
	// bound): the regression test of finding SR-21 of the review.
	reqtest.Partial(f, "FR-5.28", "FR-5.30")
	for _, s := range []string{
		"data: {\"jsonrpc\":\"2.0\"}\n\n",
		": comment\nid: 7\nretry: 100\ndata: a\ndata: b\n\n",
		"data: " + strings.Repeat("x", 300) + "\n\n",
		"id: a\x00b\r\ndata: x\r\r",
		"data:x\rdata:y\n\nid:\n\n",
		strings.Repeat(":", 5000),
	} {
		f.Add([]byte(s), 64)
	}
	f.Fuzz(func(t *testing.T, in []byte, limit int) {
		if limit < 1 || limit > 1<<16 {
			limit = 64
		}
		rd := newSSEReader(bytes.NewReader(in), limit)
		for n := 0; ; n++ {
			if n > len(in)+1 {
				t.Fatal("more events than input bytes")
			}
			ev, err := rd.Next()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("error %v", err)
				}
				return
			}
			if len(ev.Data) > limit {
				t.Fatalf("event data %d bytes over the bound %d", len(ev.Data), limit)
			}
			if len(ev.ID) > 1024 || strings.ContainsAny(ev.ID, "\x00\r\n") {
				t.Fatalf("event ID %q", ev.ID)
			}
		}
	})
}

// FuzzEncodeValue: an Mcp-Name or Mcp-Param-* value is always header text
// (visible ASCII, space or tab, no leading or trailing white space) and
// decodes to the original.
func FuzzEncodeValue(f *testing.F) {
	reqtest.Partial(f, "FR-5.29") // the encoding rules, for any value
	for _, s := range []string{"us-west1", "Hello, 世界", " padded ", "a\r\nX-Injected: 1", "=?base64?x?=", "\x00", "\xff\xfe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		e := EncodeValue(v)
		for i := 0; i < len(e); i++ {
			if c := e[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
				t.Fatalf("encoded %q has byte %#x", e, c)
			}
		}
		if e != "" && (isWS(e[0]) || isWS(e[len(e)-1])) {
			t.Fatalf("encoded %q starts or ends with white space", e)
		}
		if d, ok := DecodeValue(e); !ok || d != v {
			t.Fatalf("round trip %q -> %q -> %q (%v)", v, e, d, ok)
		}
	})
}

// FuzzHeaderParams: a server's input schema never yields a header name
// that is not an RFC 9110 token, so mirrored arguments cannot add or split
// headers.
func FuzzHeaderParams(f *testing.F) {
	reqtest.Partial(f, "FR-5.29") // mirrored header names, for any schema
	for _, s := range []string{
		`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`,
		`{"properties":{"a":{"type":"string","x-mcp-header":"X: y\r\nEvil"}}}`,
		`{"properties":{"a":{"properties":{"b":{"type":"integer","x-mcp-header":"B"}}}}}`,
		`[]`, `null`, `{"properties":{"a":1}}`,
	} {
		f.Add([]byte(s), []byte(`{"region":"eu","a":{"b":3}}`))
	}
	f.Fuzz(func(t *testing.T, schema, args []byte) {
		ps, ok := headerParams(json.RawMessage(schema))
		if !ok && len(ps) > 0 {
			t.Fatal("invalid annotations returned parameters")
		}
		for _, p := range ps {
			if !validToken(p.name) {
				t.Fatalf("header name %q is not a token", p.name)
			}
		}
		h := make(map[string][]string)
		setParamHeaders(h, ps, json.RawMessage(args))
		for k, vs := range h {
			if !strings.HasPrefix(k, HeaderParamPrefix) {
				t.Fatalf("header %q outside %s", k, HeaderParamPrefix)
			}
			for _, v := range vs {
				if strings.ContainsAny(v, "\r\n\x00") {
					t.Fatalf("header %s value %q", k, v)
				}
			}
		}
	})
}
