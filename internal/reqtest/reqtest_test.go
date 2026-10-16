package reqtest

import (
	"strings"
	"testing"
)

type recorder struct {
	testing.TB
	logs  []string
	fatal string
}

func (r *recorder) Helper()                           {}
func (r *recorder) Log(args ...any)                   { r.logs = append(r.logs, args[0].(string)) }
func (r *recorder) Fatalf(format string, args ...any) { r.fatal = format }

func TestMarkers(t *testing.T) {
	r := &recorder{TB: t}
	Verifies(r, "FR-1.2", "SR-2.9-1")
	Partial(r, "FR-4.5")
	if len(r.logs) != 2 || r.logs[0] != "VERIFIES: FR-1.2 SR-2.9-1" || r.logs[1] != "PARTIAL: FR-4.5" {
		t.Fatalf("%q", r.logs)
	}
	Partial(r, "FR4.5")
	if !strings.Contains(r.fatal, "not a requirement ID") {
		t.Fatalf("bad ID accepted: %q", r.fatal)
	}
}
