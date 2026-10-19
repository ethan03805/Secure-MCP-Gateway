package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func callEvents(corr, tool string, steps ...[3]string) []audit.Event {
	var evs []audit.Event
	for _, s := range steps {
		class := "call"
		if s[0] == string(audit.PhaseAuthorized) || s[0] == string(audit.PhaseDenied) {
			class = "decision"
		}
		evs = append(evs, audit.Event{Class: class, Phase: audit.Phase(s[0]), Outcome: s[1], ReasonCode: s[2],
			CorrelationID: corr, SessionID: "s1", ToolRevision: "live-abc/" + tool})
	}
	return evs
}

// timed stamps every event with t.
func timed(evs []audit.Event, t time.Time) []audit.Event {
	for i := range evs {
		evs[i].Time = t.Format(time.RFC3339Nano)
	}
	return evs
}

var delivered = [][3]string{{"requested", "", ""}, {"authorized", "permit", "PERMIT"}, {"dispatched", "", ""}, {"completed", "ok", ""}, {"delivered", "release", ""}}

func TestJournalAssertions(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")

	t.Run("allowed", func(t *testing.T) {
		if err := checkAllowed(callEvents("c1", toolAllowed, delivered...)); err != nil {
			t.Fatal(err)
		}
		if err := checkAllowed(nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("no events: %v", err)
		}
		// Requested but never delivered.
		if err := checkAllowed(callEvents("c1", toolAllowed, delivered[:3]...)); err == nil {
			t.Fatal("undelivered call accepted")
		}
		// A delivered call to another tool does not count.
		if err := checkAllowed(callEvents("c1", toolApproval, delivered...)); err == nil {
			t.Fatal("call to another tool accepted")
		}
	})

	t.Run("denied", func(t *testing.T) {
		refused := callEvents("c2", toolLimited, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "RATE_LIMITED"})
		if err := checkDenied(refused, nil); err != nil {
			t.Fatal(err)
		}
		if err := checkDenied(callEvents("c2", toolLimited, delivered...), nil); err == nil {
			t.Fatal("dispatched call accepted as a denial")
		}
		other := callEvents("c2", toolLimited, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "NO_PERMIT"})
		if err := checkDenied(other, nil); err == nil {
			t.Fatal("wrong reason code accepted")
		}
	})

	// A dispatched call is a Gateway fault when the session's window was
	// full (a call permitted less than a minute earlier) and a deny
	// precondition failure (errWindowOpen) when it was empty, as in Real
	// agents run 39279945533 where the probe's fill before the retry never
	// reached the Gateway.
	t.Run("denied window", func(t *testing.T) {
		t0 := time.Date(2026, 10, 19, 15, 45, 12, 0, time.UTC)
		fill := timed(callEvents("fill", toolLimited, delivered...), t0)
		agent := func(after time.Duration) []audit.Event {
			return timed(callEvents("agent", toolLimited, delivered...), t0.Add(after))
		}
		err := checkDenied(agent(30*time.Second), fill)
		if err == nil || errors.Is(err, errWindowOpen) || !strings.Contains(err.Error(), "Gateway fault") {
			t.Fatalf("dispatch inside a full window: %v", err)
		}
		// Any permitted call of the session fills the window, not only one
		// to the rate-limited tool.
		echo := timed(callEvents("echo", toolAllowed, delivered...), t0)
		if err := checkDenied(agent(10*time.Second), echo); err == nil || errors.Is(err, errWindowOpen) {
			t.Fatalf("dispatch inside a window filled by another tool: %v", err)
		}
		// The fill of the same attempt counts too (in evs, not prior).
		if err := checkDenied(append(slices.Clone(fill), agent(5*time.Second)...), nil); err == nil || errors.Is(err, errWindowOpen) {
			t.Fatalf("dispatch after a fill in the same attempt: %v", err)
		}
		err = checkDenied(agent(6*time.Minute+57*time.Second), fill)
		if !errors.Is(err, errWindowOpen) || !strings.Contains(err.Error(), "not a Gateway fault") {
			t.Fatalf("dispatch after the window ended: %v", err)
		}
		if err := checkDenied(agent(0), nil); !errors.Is(err, errWindowOpen) {
			t.Fatalf("dispatch with no earlier permitted call: %v", err)
		}
		// A dispatched call without a permit decision is never excused.
		bare := callEvents("agent", toolLimited, [3]string{"requested", "", ""}, [3]string{"dispatched", "", ""})
		if err := checkDenied(bare, nil); err == nil || errors.Is(err, errWindowOpen) {
			t.Fatalf("dispatch without a permit: %v", err)
		}
	})

	t.Run("fill", func(t *testing.T) {
		if o, err := fillOutcome(callEvents("f", toolLimited, delivered...)); err != nil || o != fillPermitted {
			t.Fatalf("permitted fill: %q %v", o, err)
		}
		refused := callEvents("f", toolLimited, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "RATE_LIMITED"})
		if o, err := fillOutcome(refused); err != nil || o != fillRateLimited {
			t.Fatalf("refused fill: %q %v", o, err)
		}
		if _, err := fillOutcome(nil); err == nil || !strings.Contains(err.Error(), "did not reach the Gateway") {
			t.Fatalf("fill that never reached the Gateway: %v", err)
		}
		other := callEvents("f", toolLimited, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "NO_PERMIT"})
		if _, err := fillOutcome(other); err == nil {
			t.Fatal("fill refused for another reason accepted")
		}
	})

	t.Run("approval", func(t *testing.T) {
		appr := func(outcome string) audit.Event {
			return audit.Event{Class: "approval", Outcome: outcome, SessionID: "s1", Detail: map[string]any{"tool": toolApproval}}
		}
		evs := append([]audit.Event{appr("requested"), appr("approved"), appr("consumed")}, callEvents("c3", toolApproval, delivered...)...)
		if err := checkApproval(evs, true); err != nil {
			t.Fatal(err)
		}
		if err := checkApproval(append([]audit.Event{appr("requested")}, callEvents("c3", toolApproval, delivered...)...), true); err == nil {
			t.Fatal("delivery without an approved event accepted")
		}
		held := callEvents("c3", toolApproval, [3]string{"requested", "", ""}, [3]string{"denied", "deny", "APPROVAL_REQUIRED"})
		if err := checkApproval(held, false); err != nil {
			t.Fatalf("refusal without an approval service: %v", err)
		}
		if err := checkApproval(callEvents("c3", toolApproval, delivered...), false); err == nil {
			t.Fatal("dispatch without an approval service accepted")
		}
		if err := checkLocalRefusal(nil); err != nil {
			t.Fatal(err)
		}
		if err := checkLocalRefusal(held); err == nil {
			t.Fatal("local refusal accepted although the call reached the Gateway")
		}
	})

	t.Run("ungranted", func(t *testing.T) {
		if err := checkUngranted(callEvents("c4", toolAllowed, delivered...)); err != nil {
			t.Fatal(err)
		}
		if err := checkUngranted(callEvents("c4", toolUngranted, delivered...)); err == nil {
			t.Fatal("call to the ungranted tool accepted")
		}
	})

	t.Run("signin", func(t *testing.T) {
		ok := audit.Event{Class: "session", SessionID: "s1", Outcome: "created", ReasonCode: "OAUTH_CODE", PrincipalID: "agents-x",
			Detail: map[string]any{"template": templateID}}
		if err := checkSignIn([]audit.Event{ok}, "s1", "agents-x"); err != nil {
			t.Fatal(err)
		}
		bad := ok
		bad.ReasonCode = "SESSION_API"
		if err := checkSignIn([]audit.Event{bad}, "s1", "agents-x"); err == nil {
			t.Fatal("non-OAuth session accepted")
		}
		if err := checkSignIn([]audit.Event{ok}, "s1", "agents-y"); err == nil {
			t.Fatal("wrong principal accepted")
		}
		if err := checkSignIn(nil, "s1", "agents-x"); err == nil {
			t.Fatal("missing session accepted")
		}
	})

	t.Run("catalog", func(t *testing.T) {
		if err := checkCatalog([]string{"ref_echo", "ref_read_file", "ref_time_now"}); err != nil {
			t.Fatal(err)
		}
		if err := checkCatalog([]string{"ref_echo", "ref_list_files", "ref_read_file", "ref_time_now"}); err == nil {
			t.Fatal("ungranted tool in the catalog accepted")
		}
	})
}

func TestSessionEventsWindow(t *testing.T) {
	evs := []audit.Event{{SessionID: "a"}, {SessionID: "b"}, {SessionID: "a", Class: "x"}}
	got := sessionEvents(evs, 1, "a")
	if len(got) != 1 || got[0].Class != "x" {
		t.Fatalf("got %+v", got)
	}
	if got := sessionEvents(evs, 10, "a"); len(got) != 0 {
		t.Fatalf("index past the end: %+v", got)
	}
	if backendTool(audit.Event{ToolRevision: "live-1/read_file"}) != "read_file" || backendTool(audit.Event{}) != "" {
		t.Fatal("backendTool")
	}
}
