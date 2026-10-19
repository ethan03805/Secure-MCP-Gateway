package edge

import (
	"bytes"
	"encoding/json"
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

	// The six tray states of FR-20.2, plus the variant for a degraded
	// Gateway that is not labelled enforced (a Standalone installation is
	// never healthy, FR-13.10).
	controls := map[string]bool{"open-console": true, "start": true, "restart": true}
	for _, s := range []string{"healthy", "degraded", "degraded-not-enforced", "fail-closed", "emergency-stop", "stopped", "unreachable"} {
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
}
