package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// callRun carries one tool call through the pipeline and writes its
// evidence. record appends; commit appends and waits for fsync. A failure of
// either is returned so the stage can fail closed.
type callRun struct {
	g    *Gateway
	base audit.Event
	corr string
	dec  policy.Decision
}

func (c *callRun) event(class string, phase audit.Phase, origin, outcome, reason, status string, detail any) audit.Event {
	e := c.base
	e.Class, e.Phase, e.Origin, e.Outcome, e.ReasonCode, e.PolicyStatus, e.Detail = class, phase, origin, outcome, reason, status, detail
	e.DecisionID, e.PolicyRevision = c.dec.ID, c.dec.PolicyRevision
	return e
}

func (c *callRun) record(class string, phase audit.Phase, origin, outcome, reason, status string) error {
	return c.g.evidence.Record(c.event(class, phase, origin, outcome, reason, status, nil))
}

func (c *callRun) commit(class string, phase audit.Phase, origin, outcome, reason, status string, detail any) error {
	return c.g.evidence.Commit(c.event(class, phase, origin, outcome, reason, status, detail))
}

// refuse commits a terminal refusal event and returns err. A refusal is the
// safe outcome, so it is returned even when its evidence cannot be written;
// the failure is logged and the journal's sticky error fails the Gateway
// closed for later calls.
func (c *callRun) refuse(err *jsonrpc.Error, class string, phase audit.Phase, origin, outcome, reason, status string) error {
	if aerr := c.commit(class, phase, origin, outcome, reason, status, nil); aerr != nil {
		c.g.log.Error("evidence write failed", "err", aerr, "correlation", c.corr)
	}
	return err
}

func (c *callRun) auditFailure(err error) error {
	c.g.log.Error("evidence write failed; refusing call", "err", err, "correlation", c.corr)
	return gatewayError(CodeGatewayFailClosed, "gateway fail-closed: evidence unavailable", ReasonAuditUnavailable, c.corr, c.dec.ID, nil)
}

// toolHandler is the per-call enforcement pipeline (FR-4.3): authenticate
// (mcpChain), session check, decision, request inspection, approval,
// launch authorization, dispatch, response inspection, release
// authorization. Request and response scoring (E-31) are not yet stages.
func (g *Gateway) toolHandler(sess session.Session, ref *backend.ToolRef) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		corr, _ := ctx.Value(ctxCorrelation).(string)
		if corr == "" {
			corr = ids.New()
		}
		// FR-2.11: ending the session cancels this call.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		defer g.trackCall(sess.ID, cancel)()

		c := &callRun{g: g, corr: corr, base: audit.Event{CorrelationID: corr, SessionID: sess.ID, PrincipalID: sess.PrincipalID,
			ServerRevision: ref.Server.Revision, ToolRevision: ref.Revision}}
		side, trust := toolClasses(ref)
		// The requested event carries the canonical request, so that policy
		// simulation can replay recorded calls (FR-3.5).
		if err := g.evidence.Record(c.event("call", audit.PhaseRequested, "E-02", "", "", "not_evaluated", map[string]any{
			"server": ref.Server.Alias, "tool": ref.Tool.Name, "template": sess.Template, "profile": sess.Profile,
			"side_effect": side, "source_trust": trust})); err != nil {
			return nil, c.auditFailure(err)
		}

		// Session check: the request was authenticated, but the session may
		// have ended since.
		if !g.store.IsActive(sess.ID) {
			return nil, c.refuse(gatewayError(CodeSessionInvalid, "session invalid", ReasonSessionState, corr, "", nil),
				"call", audit.PhaseDenied, "E-04", "deny", ReasonSessionState, "not_evaluated")
		}
		if reason := g.failClosed(); reason != "" {
			return nil, c.refuse(gatewayError(CodeGatewayFailClosed, "gateway fail-closed", reason, corr, "", nil),
				"call", audit.PhaseDenied, "E-12", "deny", reason, "unavailable")
		}

		// Decision (SR-5.5-1: every call is evaluated).
		c.dec = g.decider.Decide(policy.Request{PrincipalID: sess.PrincipalID, SessionID: sess.ID, Profile: sess.Profile, Template: sess.Template,
			Server: ref.Server.Alias, Tool: ref.Tool.Name, SideEffect: side, SourceTrust: trust})
		dec := c.dec
		if dec.Outcome != policy.Permit {
			var e *jsonrpc.Error
			switch dec.ReasonCode {
			case policy.ReasonRateLimited:
				e = gatewayError(CodeRateLimited, "rate limited", dec.ReasonCode, corr, dec.ID, map[string]any{"callsPerMinute": dec.Obligations.CallsPerMinute, "burst": dec.Obligations.Burst})
			case policy.ReasonQuota:
				e = gatewayError(CodeRateLimited, "session quota exhausted", dec.ReasonCode, corr, dec.ID, map[string]any{"callsPerSession": dec.Obligations.CallsPerSession})
			case policy.ReasonNoSnapshot:
				e = gatewayError(CodeGatewayFailClosed, "gateway fail-closed", dec.ReasonCode, corr, dec.ID, nil)
			default:
				e = gatewayError(CodePolicyDenied, "policy denied", dec.ReasonCode, corr, dec.ID, map[string]any{"decisiveRules": dec.DecisiveRules})
			}
			return nil, c.refuse(e, "decision", audit.PhaseDenied, "E-06", "deny", dec.ReasonCode, "evaluated")
		}

		call := &pipeline.Call{CorrelationID: corr, SessionID: sess.ID, PrincipalID: sess.PrincipalID, Template: sess.Template,
			Purpose: sess.Purpose, Project: sess.Project, EndUser: sess.EndUser, Server: ref.Server.Alias, Tool: ref.Tool.Name,
			PublicName: ref.Public, ServerRevision: ref.Server.Revision, ToolRevision: ref.Revision, ManifestSource: ref.Server.ManifestSource,
			DecisionID: dec.ID, PolicyRevision: dec.PolicyRevision, Obligations: dec.Obligations, DecisiveRules: dec.DecisiveRules,
			InputSchema: ref.Tool.InputSchema, OutputSchema: ref.Tool.OutputSchema}

		// Request inspection (E-09).
		args, reqApplied, verdict := g.filters.RunRequest(ctx, call, req.Params.Arguments)
		if verdict != nil && ctx.Err() != nil && !g.store.IsActive(sess.ID) {
			// FR-2.11: the session ended while the filters ran; their
			// cancellation verdict is not an inspection finding.
			return nil, c.refuse(gatewayError(CodeSessionInvalid, "session ended during the call", ReasonSessionEnded, corr, dec.ID, nil),
				"call", audit.PhaseIndeterminate, "E-04", "cancelled", ReasonSessionEnded, "evaluated")
		}
		if verdict != nil {
			var e *jsonrpc.Error
			if verdict.ReasonCode == pipeline.ReasonSchemaInvalid {
				raw, _ := json.Marshal(map[string]any{"reasonCode": verdict.ReasonCode, "correlationId": corr, "decisionId": dec.ID, "findings": verdict.Finding,
					"message": Message(jsonrpc.CodeInvalidParams, verdict.ReasonCode, nil)})
				e = &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "arguments do not match the tool schema", Data: raw}
			} else {
				e = gatewayError(CodePolicyDenied, "request blocked by inspection", verdict.ReasonCode, corr, dec.ID, map[string]any{"findings": verdict.Finding, "filters": reqApplied})
			}
			return nil, c.refuse(e, "filter", audit.PhaseFiltered, "E-09", "block", verdict.ReasonCode, "evaluated")
		}

		// Approval (E-07).
		if dec.Obligations.Approval {
			if err := g.approve(ctx, c, call, args, req); err != nil {
				return nil, err
			}
		}

		// Launch authorization under the barrier (FR-4.13, SR-1.17-1,
		// SR-6.2-1): the decision intent is committed before the capability
		// exists.
		binding := pipeline.Binding{CorrelationID: corr, DecisionID: dec.ID, PolicyRevision: dec.PolicyRevision, PublicName: ref.Public}
		capID, err := g.authorizeLaunch(c, sess.ID, binding)
		if err != nil {
			return nil, err
		}

		// Dispatch (FR-4.8, FR-4.9, FR-4.10) with the one-use capability.
		if err := c.record("call", audit.PhaseDispatched, "E-10", "", "", "evaluated"); err != nil {
			return nil, c.auditFailure(err)
		}
		cctx, ccancel := context.WithTimeout(ctx, g.cfg.Limits.ClientDeadline.Duration) // CP-13 client deadline (FR-1.43)
		defer ccancel()
		res, err := g.reg.Call(cctx, backend.Dispatch{Principal: sess.PrincipalID, Ref: ref, Arguments: args,
			Capability: capID, Binding: binding})
		if err != nil {
			return nil, g.mapDispatchError(c, sess.ID, err)
		}

		// Response inspection (E-11).
		res, respApplied, rv := g.filters.RunResponse(ctx, call, res)
		if rv != nil {
			return nil, c.refuse(gatewayError(CodeResponseWithheld, "response withheld", rv.ReasonCode, corr, dec.ID, map[string]any{"findings": rv.Finding}),
				"filter", audit.PhaseWithheld, "E-11", "withhold", rv.ReasonCode, "evaluated")
		}
		// Provenance (FR-4.12, SR-5.13-1).
		if res.Meta == nil {
			res.Meta = mcp.Meta{}
		}
		applied := append(append([]string{}, reqApplied...), respApplied...)
		prov := map[string]any{
			"serverId": ref.Server.Alias, "serverRevision": ref.Server.Revision, "toolRevision": ref.Revision,
			"decisionId": dec.ID, "filters": applied, "manifest": ref.Server.ManifestSource, "untrusted": true,
			"disposition": call.Inspection.Disposition(), // FR-4.11
		}
		if tags := call.Inspection.Tags(); len(tags) > 0 { // FR-4.17
			prov["tags"] = tags
		}
		res.Meta[metaPrefix+"provenance"] = prov

		outcome := "ok"
		if res.IsError {
			outcome = "tool_error"
		}
		if err := c.record("call", audit.PhaseCompleted, "E-10", outcome, "", "evaluated"); err != nil {
			return nil, c.auditFailure(err)
		}
		// Release authorization under the barrier (SR-1.17-2); the delivered
		// event is durable before the result leaves.
		if err := g.authorizeRelease(c, sess.ID); err != nil {
			return nil, err
		}
		if dec.TaintsSession { // SR-5.13-2: untrusted content reached the session
			g.decider.Taint(sess.ID)
		}
		return res, nil
	}
}

// approve runs the approval stage (FR-3.14 to FR-3.22). It returns nil when
// the call may continue. While the Approver holds the call, its Progress
// calls commit the response to an event stream and send keep-alives
// (stream.go).
func (g *Gateway) approve(ctx context.Context, c *callRun, call *pipeline.Call, args json.RawMessage, req *mcp.CallToolRequest) error {
	res, err := g.approver.Request(ctx, pipeline.ApprovalRequest{Call: *call, Arguments: args, Hold: g.cfg.Limits.ApprovalHold.Duration, Progress: g.keepAlive(ctx, req)})
	if err != nil {
		g.log.Warn("approval service failed; refusing the call", "err", err, "correlation", c.corr)
		res = pipeline.ApprovalResult{Outcome: pipeline.Pending, ReasonCode: ReasonApprovalNoSvc,
			RetryText: "The approval service is unavailable. Retry later or ask the operator."}
	}
	detail := map[string]any{"approval_id": res.ApprovalID, "approver": res.Approver}
	switch res.Outcome {
	case pipeline.Approved:
		if err := c.commit("approval", audit.PhaseAuthorized, "E-07", "approved", "APPROVED", "evaluated", detail); err != nil {
			return c.auditFailure(err)
		}
		return nil
	case pipeline.Denied:
		reason := res.ReasonCode
		if reason == "" {
			reason = ReasonApprovalDenied
		}
		extra := map[string]any{}
		if res.ApprovalID != "" {
			extra["approvalId"] = res.ApprovalID
		}
		return c.refuse(gatewayError(CodePolicyDenied, "approval denied", reason, c.corr, c.dec.ID, extra),
			"approval", audit.PhaseDenied, "E-07", "deny", reason, "evaluated")
	default:
		reason := res.ReasonCode
		if reason == "" || (reason == pipeline.ReasonApprovalRequired && call.Obligations.ApprovalReason != "") {
			reason = pipeline.ReasonApprovalRequired
			if call.Obligations.ApprovalReason != "" { // TAINT_APPROVAL
				reason = call.Obligations.ApprovalReason
			}
		}
		extra := map[string]any{"retry": res.RetryText}
		link := res.ConsoleURL
		if link == "" && g.consoleURL != "" {
			link = g.consoleURL + "/approvals?correlation=" + url.QueryEscape(c.corr)
		}
		if link != "" {
			extra["consoleUrl"] = link // retained for clients of the first slice
			extra["approvalUrl"] = link
		}
		if res.ApprovalID != "" {
			extra["approvalId"] = res.ApprovalID
		}
		if !res.ExpiresAt.IsZero() {
			extra["expiresAt"] = res.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return c.refuse(gatewayError(CodeApprovalRequired, "approval required", reason, c.corr, c.dec.ID, extra),
			"approval", audit.PhaseDenied, "E-07", "pending", reason, "evaluated")
	}
}

// authorizeLaunch rechecks state under the barrier, commits the decision
// intent ("authorized") durably and only then issues the capability.
func (g *Gateway) authorizeLaunch(c *callRun, sessionID string, b pipeline.Binding) (string, error) {
	g.gate.RLock()
	defer g.gate.RUnlock()
	reason := ""
	switch {
	case g.stopped.Load():
		reason = ReasonEmergencyStop
	case g.decider.Snapshot() == nil || g.decider.Snapshot().Revision != b.PolicyRevision:
		reason = ReasonRevisionChanged
	case !g.store.IsActive(sessionID):
		reason = ReasonSessionState
	case g.evidenceErr() != nil:
		reason = ReasonAuditUnavailable
	case len(g.healthGate()) > 0: // E-23 critical cause (SR-6.11-1, SR-7.10-1)
		reason = ReasonFailClosed
	}
	if reason != "" {
		return "", c.refuse(gatewayError(CodeGatewayFailClosed, "launch refused", reason, c.corr, c.dec.ID, nil),
			"call", audit.PhaseDenied, "E-12", "deny", reason, "evaluated")
	}
	if err := c.commit("decision", audit.PhaseAuthorized, "E-12", "permit", c.dec.ReasonCode, "evaluated", nil); err != nil {
		return "", c.auditFailure(err)
	}
	return g.caps.Issue(b), nil
}

// authorizeRelease rechecks session and stop state under the barrier and
// commits the delivered event before the result is released.
func (g *Gateway) authorizeRelease(c *callRun, sessionID string) error {
	g.gate.RLock()
	defer g.gate.RUnlock()
	reason := ""
	switch {
	case g.stopped.Load():
		reason = ReasonEmergencyStop
	case !g.store.IsActive(sessionID):
		reason = ReasonSessionState
	}
	if reason != "" {
		return c.refuse(gatewayError(CodeResponseWithheld, "response withheld", reason, c.corr, c.dec.ID, nil),
			"call", audit.PhaseWithheld, "E-12", "withhold", reason, "evaluated")
	}
	if err := c.commit("call", audit.PhaseDelivered, "E-12", "release", "", "evaluated", nil); err != nil {
		return c.auditFailure(err)
	}
	return nil
}

// mapDispatchError maps a dispatcher error to an Appendix B error and
// writes the terminal event (failed, indeterminate, withheld or denied) for
// every path.
func (g *Gateway) mapDispatchError(c *callRun, sessionID string, err error) error {
	corr, dec := c.corr, c.dec
	var be *backend.BackendError
	var ce *backend.CapabilityError
	var we *jsonrpc.Error
	switch {
	case errors.As(err, &ce):
		return c.refuse(gatewayError(CodeGatewayFailClosed, "dispatch refused", ReasonCapability, corr, dec.ID, nil),
			"call", audit.PhaseDenied, "E-10", "deny", ReasonCapability, "evaluated")
	case errors.As(err, &be): // FR-1.32
		return c.refuse(gatewayError(CodeBackendError, "backend error", "BACKEND_ERROR", corr, dec.ID, map[string]any{"backendCode": be.Code}),
			"call", audit.PhaseFailed, "E-10", "backend_error", "BACKEND_ERROR", "evaluated")
	case errors.Is(err, backend.ErrQueueFull):
		return c.refuse(gatewayError(CodeRateLimited, "dispatch queue full", "QUEUE_FULL", corr, dec.ID, nil),
			"call", audit.PhaseDenied, "E-10", "deny", "QUEUE_FULL", "evaluated")
	case errors.Is(err, backend.ErrTimeout):
		return c.refuse(gatewayError(CodeTimeout, "upstream timeout", "UPSTREAM_TIMEOUT", corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-10", "timeout", "UPSTREAM_TIMEOUT", "evaluated")
	case errors.Is(err, backend.ErrTooLarge):
		return c.refuse(gatewayError(CodeResponseWithheld, "response withheld", "RESULT_TOO_LARGE", corr, dec.ID, nil),
			"call", audit.PhaseWithheld, "E-11", "withhold", "RESULT_TOO_LARGE", "evaluated")
	case errors.Is(err, context.DeadlineExceeded):
		return c.refuse(gatewayError(CodeTimeout, "client deadline expired", "CLIENT_DEADLINE", corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-10", "timeout", "CLIENT_DEADLINE", "evaluated")
	case errors.Is(err, context.Canceled) && !g.store.IsActive(sessionID):
		return c.refuse(gatewayError(CodeSessionInvalid, "session ended during the call", ReasonSessionEnded, corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-04", "cancelled", ReasonSessionEnded, "evaluated")
	case errors.Is(err, context.Canceled):
		return c.refuse(gatewayError(CodeIndeterminate, "call cancelled", "CANCELLED", corr, dec.ID, nil),
			"call", audit.PhaseIndeterminate, "E-10", "cancelled", "CANCELLED", "evaluated")
	case errors.As(err, &we):
		return c.refuse(we, "call", audit.PhaseFailed, "E-10", "failed", "INVALID_ARGUMENTS", "evaluated")
	}
	return c.refuse(gatewayError(CodeBackendError, "dispatch failed", "DISPATCH_FAILED", corr, dec.ID, nil),
		"call", audit.PhaseFailed, "E-10", "failed", "DISPATCH_FAILED", "evaluated")
}

// toolClasses returns the side-effect class and source trust a verified
// manifest declares for the tool. An unverified (live) tool list is the
// server describing itself, so it classifies nothing.
func toolClasses(ref *backend.ToolRef) (side, trust string) {
	if !ref.Server.Verified || ref.Tool == nil {
		return "", ""
	}
	side, _ = ref.Tool.Meta[policy.MetaSideEffect].(string)
	trust, _ = ref.Tool.Meta[policy.MetaSourceTrust].(string)
	return side, trust
}
