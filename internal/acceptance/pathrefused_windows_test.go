//go:build windows

package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsPathRefusedEndToEnd: through the harness listener of a
// running per-user Gateway, a path argument in a Windows-only form (an
// alternate data stream, a reserved device name, a UNC host, a device
// prefix) is refused before dispatch with -31001, reason PATH_REFUSED and
// the Appendix B Table B.2 message, which docs/design/messages.json holds
// word for word (FR-21.25). internal/e2e.TestEveryReasonCodeEndToEnd
// (FR-1.51) names this test for the reason code, whose forms exist on
// Windows only.
func TestWindowsPathRefusedEndToEnd(t *testing.T) {
	needBinaries(t)
	reqtest.Partial(t, "FR-21.25")
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		ReasonCodes map[string]struct {
			Message string `json:"message"`
		} `json:"reasonCodes"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	want := cat.ReasonCodes["PATH_REFUSED"].Message
	if want == "" {
		t.Fatal("PATH_REFUSED is not in docs/design/messages.json")
	}
	g := newGateway(t, options{})
	g.start()
	tok := g.token("")
	for i, p := range []string{`inside.txt:hidden`, `NUL`, `sub\COM1.txt`, `\\host\share\x`, `\\?\C:\Windows\win.ini`} {
		args, _ := json.Marshal(map[string]any{"path": p})
		resp, body := g.mcpPost(tok, wireCall(100+i, "ref_read_file", string(args), ""), wireHeaders("tools/call", "ref_read_file"))
		var msg struct {
			Error *struct {
				Code int64 `json:"code"`
				Data struct {
					ReasonCode string `json:"reasonCode"`
					Message    string `json:"message"`
				} `json:"data"`
			} `json:"error"`
		}
		payload := body
		if i := strings.Index(body, "data: {"); i >= 0 { // an SSE response
			payload, _, _ = strings.Cut(body[i+len("data: "):], "\n")
		}
		if err := json.Unmarshal([]byte(payload), &msg); err != nil || msg.Error == nil {
			t.Fatalf("%s: %d %s", p, resp.StatusCode, body)
		}
		if msg.Error.Code != -31001 || msg.Error.Data.ReasonCode != "PATH_REFUSED" || msg.Error.Data.Message != want {
			t.Errorf("%s: code %d reason %q message %q", p, msg.Error.Code, msg.Error.Data.ReasonCode, msg.Error.Data.Message)
		}
	}
}
