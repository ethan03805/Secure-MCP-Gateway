package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// The functions here make every scenario's pass/fail decision from the
// Gateway's evidence journal, never from the model's text. Each takes the
// events of one session written after a scenario started (sinceIndex) and
// returns nil or the reason the scenario failed.

// errNoCall: the agent made no call to the scenario's tool at all; the
// journal holds no call event for it in this session since the scenario
// started. runChecked retries it (see there).
var errNoCall = errors.New("the agent made no call")

// errWindowOpen: the agent's call to the rate-limited tool was dispatched,
// but no call of the session had been permitted within the minute before
// it, so the session's one-call-per-minute window was empty and permitting
// the call was the policy's correct answer. The denied scenario's
// precondition (a full window) did not hold when the agent called, because
// the agent called more than a minute after the probe filled the window.
// That says nothing about enforcement, so it is kept apart from a dispatch
// inside a full window, which is a Gateway fault. runChecked retries it.
var errWindowOpen = errors.New("deny precondition not held")

// rateWindow is the policy's sliding rate window (policy.allowLocked);
// windowSlack allows for the journal stamping an event just after the
// decider read its clock.
const (
	rateWindow  = time.Minute
	windowSlack = time.Second
)

// backendTool returns the backend tool name of a call event: the Gateway
// writes tool_revision as "<server revision>/<tool>".
func backendTool(e audit.Event) string {
	if i := strings.LastIndexByte(e.ToolRevision, '/'); i >= 0 {
		return e.ToolRevision[i+1:]
	}
	return ""
}

// sessionEvents returns the events of sessionID from index since on.
func sessionEvents(evs []audit.Event, since int, sessionID string) []audit.Event {
	if since > len(evs) {
		since = len(evs)
	}
	var out []audit.Event
	for _, e := range evs[since:] {
		if e.SessionID == sessionID {
			out = append(out, e)
		}
	}
	return out
}

// callsTo groups the call-pipeline events (classes call and decision) for a
// backend tool by correlation ID, in journal order.
func callsTo(evs []audit.Event, tool string) (order []string, by map[string][]audit.Event) {
	by = map[string][]audit.Event{}
	for _, e := range evs {
		if (e.Class != "call" && e.Class != "decision") || backendTool(e) != tool || e.CorrelationID == "" {
			continue
		}
		if _, ok := by[e.CorrelationID]; !ok {
			order = append(order, e.CorrelationID)
		}
		by[e.CorrelationID] = append(by[e.CorrelationID], e)
	}
	return order, by
}

func hasPhase(evs []audit.Event, phase audit.Phase, outcome string) bool {
	for _, e := range evs {
		if e.Phase == phase && (outcome == "" || e.Outcome == outcome) {
			return true
		}
	}
	return false
}

// checkSignIn: the session was created by the OAuth authorization-code flow
// for the agent's principal and the conformance template.
func checkSignIn(evs []audit.Event, sessionID, principal string) error {
	for _, e := range evs {
		if e.Class == "session" && e.SessionID == sessionID && e.Outcome == "created" {
			if e.ReasonCode != "OAUTH_CODE" {
				return fmt.Errorf("session created with reason %s, want OAUTH_CODE", e.ReasonCode)
			}
			if e.PrincipalID != principal {
				return fmt.Errorf("session principal %s, want %s", e.PrincipalID, principal)
			}
			if d, ok := e.Detail.(map[string]any); ok && d["template"] != templateID {
				return fmt.Errorf("session template %v, want %s", d["template"], templateID)
			}
			return nil
		}
	}
	return fmt.Errorf("no session created event for %s", sessionID)
}

// checkCatalog: the session is presented exactly the granted tools.
func checkCatalog(got []string) error {
	want := grantedTools()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("catalog %v, want %v", got, want)
	}
	return nil
}

// checkUngranted: no call to the ungranted tool reached the pipeline for
// this session, at any time.
func checkUngranted(evs []audit.Event) error {
	if order, _ := callsTo(evs, toolUngranted); len(order) > 0 {
		return fmt.Errorf("%d call(s) to ungranted %s reached the call pipeline", len(order), toolUngranted)
	}
	return nil
}

// checkAllowed: at least one call to the allowed tool was requested,
// authorized with PERMIT and delivered.
func checkAllowed(evs []audit.Event) error {
	order, by := callsTo(evs, toolAllowed)
	if len(order) == 0 {
		return fmt.Errorf("%w to %s", errNoCall, publicName(toolAllowed))
	}
	for _, c := range order {
		ce := by[c]
		if hasPhase(ce, audit.PhaseRequested, "") && hasPhase(ce, audit.PhaseAuthorized, "permit") && hasPhase(ce, audit.PhaseDelivered, "release") {
			return nil
		}
	}
	return fmt.Errorf("%d call(s) to %s but none requested, authorized and delivered", len(order), publicName(toolAllowed))
}

// checkDenied: the agent's call to the rate-limited tool was refused by the
// decision with RATE_LIMITED and never dispatched. evs are the session's
// events since the prompt started; prior are its events before that, which
// hold the probe's call that filled the rate window.
//
// A dispatched call is classified by the session's rate window at its
// decision. The Gateway counts every permitted call of a session in the
// session window, so for a tool limited to one call per minute any call of
// the session permitted less than a minute earlier fills it: then the
// dispatch is a Gateway fault. Otherwise the window was empty, the
// precondition did not hold, and the error wraps errWindowOpen.
func checkDenied(evs, prior []audit.Event) error {
	order, by := callsTo(evs, toolLimited)
	if len(order) == 0 {
		return fmt.Errorf("%w to %s", errNoCall, publicName(toolLimited))
	}
	// Every dispatched call is classified; one inside a full window makes
	// the scenario a Gateway fault whatever the others were.
	var open error
	for _, c := range order {
		ce := by[c]
		if !hasPhase(ce, audit.PhaseDispatched, "") {
			continue
		}
		err := dispatchedVerdict(c, ce, append(slices.Clip(prior), evs...))
		if !errors.Is(err, errWindowOpen) {
			return err
		}
		if open == nil {
			open = err
		}
	}
	if open != nil {
		return open
	}
	for _, c := range order {
		for _, e := range by[c] {
			if e.Phase == audit.PhaseDenied && e.Outcome == "deny" && e.ReasonCode == "RATE_LIMITED" {
				return nil
			}
		}
	}
	return fmt.Errorf("no denied event with RATE_LIMITED for %s", publicName(toolLimited))
}

// dispatchedVerdict explains why call c (events ce) to the rate-limited tool
// was dispatched, from the permitted calls among the session's events all.
func dispatchedVerdict(c string, ce, all []audit.Event) error {
	at, ok := permitTime(ce)
	if !ok {
		return fmt.Errorf("call %s to %s was dispatched without a timed permit decision; want a refusal (Gateway fault)", c, publicName(toolLimited))
	}
	var last time.Time
	lastID := ""
	seen := map[string]bool{c: true}
	for _, e := range all {
		if e.Class != "decision" || e.Phase != audit.PhaseAuthorized || e.Outcome != "permit" || seen[e.CorrelationID] {
			continue
		}
		seen[e.CorrelationID] = true // a call's first permit is the one counted
		t, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil || !t.Before(at) {
			continue
		}
		if t.After(last) {
			last, lastID = t, e.CorrelationID
		}
	}
	if lastID != "" && at.Sub(last) < rateWindow-windowSlack {
		return fmt.Errorf("call %s to %s was dispatched %s after call %s of the same session was permitted, inside the one-call-per-minute window; want a refusal with RATE_LIMITED (Gateway fault)",
			c, publicName(toolLimited), at.Sub(last).Round(time.Millisecond), lastID)
	}
	since := "no call of the session was permitted before it"
	if lastID != "" {
		since = fmt.Sprintf("the session's last permitted call (%s) was %s earlier", lastID, at.Sub(last).Round(time.Millisecond))
	}
	return fmt.Errorf("%w: call %s to %s was dispatched, but %s, so its rate window was empty and permitting it was correct; the agent called after the probe's fill had expired, which tests nothing about enforcement (harness timing, not a Gateway fault)",
		errWindowOpen, c, publicName(toolLimited), since)
}

// permitTime returns the time of a call's first permit decision.
func permitTime(ce []audit.Event) (time.Time, bool) {
	for _, e := range ce {
		if e.Class == "decision" && e.Phase == audit.PhaseAuthorized && e.Outcome == "permit" {
			t, err := time.Parse(time.RFC3339Nano, e.Time)
			return t, err == nil
		}
	}
	return time.Time{}, false
}

// Outcomes of the probe's fill call (fillOutcome).
const (
	fillPermitted   = "permitted"
	fillRateLimited = "rate-limited"
)

// fillOutcome decides the probe's fill call from the session's events
// written since it was made: fillPermitted when it was permitted (the
// window is now full for a minute), fillRateLimited when it was refused
// because an earlier window is still full, and an error when no call to the
// rate-limited tool reached the Gateway or it was decided otherwise.
func fillOutcome(evs []audit.Event) (string, error) {
	order, by := callsTo(evs, toolLimited)
	if len(order) == 0 {
		return "", fmt.Errorf("the probe's call to %s did not reach the Gateway", publicName(toolLimited))
	}
	ce := by[order[len(order)-1]]
	if hasPhase(ce, audit.PhaseAuthorized, "permit") {
		return fillPermitted, nil
	}
	for _, e := range ce {
		if e.Phase == audit.PhaseDenied && e.ReasonCode == "RATE_LIMITED" {
			return fillRateLimited, nil
		}
	}
	return "", fmt.Errorf("the probe's call to %s was neither permitted nor refused with RATE_LIMITED", publicName(toolLimited))
}

// checkApproval: the approval-obligated call was held (approval requested),
// approved by smcpctl, consumed, and the call delivered. When the build has
// no Approval Service the call must instead be refused with
// APPROVAL_REQUIRED and never dispatched.
func checkApproval(evs []audit.Event, serviceAvailable bool) error {
	order, by := callsTo(evs, toolApproval)
	if len(order) == 0 {
		return fmt.Errorf("%w to %s", errNoCall, publicName(toolApproval))
	}
	if !serviceAvailable {
		for _, c := range order {
			if hasPhase(by[c], audit.PhaseDispatched, "") {
				return fmt.Errorf("call %s was dispatched without an approval service", c)
			}
		}
		return nil
	}
	outcomes := map[string]bool{}
	for _, e := range evs {
		if e.Class == "approval" {
			if d, ok := e.Detail.(map[string]any); ok && d["tool"] == toolApproval {
				outcomes[e.Outcome] = true
			}
		}
	}
	for _, o := range []string{"requested", "approved", "consumed"} {
		if !outcomes[o] {
			return fmt.Errorf("no approval %s event for %s", o, publicName(toolApproval))
		}
	}
	for _, c := range order {
		if hasPhase(by[c], audit.PhaseDelivered, "release") {
			return nil
		}
	}
	return fmt.Errorf("approval granted but no call to %s was delivered", publicName(toolApproval))
}

// checkLocalRefusal: the client refused the approval-obligated call itself,
// so no call to that tool may have reached the Gateway.
func checkLocalRefusal(evs []audit.Event) error {
	if order, _ := callsTo(evs, toolApproval); len(order) > 0 {
		return fmt.Errorf("client reported a local refusal but %d call(s) to %s reached the Gateway", len(order), publicName(toolApproval))
	}
	return nil
}
