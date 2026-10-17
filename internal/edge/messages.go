package edge

import (
	"fmt"
	"strings"
)

// reasonMessages is SRS Appendix B Table B.2: the plain-language
// data.message of each reason code (FR-1.51). {approvalUrl} and
// {correlationId} are replaced from the error's data.
var reasonMessages = map[string]string{
	"NO_PERMIT":                  "The Gateway's policy does not allow this tool in this session. Ask the Gateway operator to grant it.",
	"NO_TEMPLATE":                "This session's policy template no longer exists. Sign in again to start a new session.",
	"PRINCIPAL_DISABLED":         "This agent's access to the Gateway is suspended. Ask the Gateway operator.",
	"CREDENTIAL_INVALID":         "This agent's Gateway credential is no longer valid. Ask the Gateway operator for a new one.",
	"REVISION_NOT_ENABLED":       "The tool's server is not enabled on the Gateway. Ask the Gateway operator.",
	"NO_ROUTE":                   "The tool's server is not available right now. Try again later or ask the Gateway operator.",
	"AMBIGUOUS_ROUTE":            "The Gateway could not choose how to reach this tool and refused the call. Ask the Gateway operator.",
	"HIGH_RISK_UNFLAGGED":        "This tool is in a high-risk class that this session's policy does not allow.",
	"APPROVAL_DENIED":            "A person reviewing this call denied it.",
	"TAINT_DENIED":               "This session has read untrusted content, so tools that write or send data are blocked. Start a new session to use them.",
	"APPROVAL_REQUIRED":          "This call needs approval. Open {approvalUrl} to approve it, then run the same request again.",
	"TAINT_APPROVAL":             "This session has read untrusted content, so this tool needs approval. Open {approvalUrl} to approve it, then run the same request again.",
	"FILTER_BLOCKED":             "The tool's result was withheld by a Gateway content filter. The operator can see why in the audit record {correlationId}.",
	"SECRET_LEAK":                "The tool's result was withheld because it appeared to contain a protected secret.",
	"RESULT_TOO_LARGE":           "The tool's result was too large to inspect and was withheld. Narrow the request.",
	"RELEASE_REFUSED":            "The result was withheld because the session or policy changed while the tool ran. Run the request again.",
	"FAIL_CLOSED":                "The Gateway is not accepting tool calls right now because a safety check failed. The operator can see the cause with `smcpctl health`.",
	"EMERGENCY_STOP":             "The Gateway operator has stopped all tool calls.",
	"NO_SNAPSHOT":                "The Gateway has no valid policy loaded and is refusing all tool calls.",
	"JOURNAL_UNAVAILABLE":        "The Gateway could not record this call and did not run it. The operator can see the cause with `smcpctl health`.",
	"POLICY_REVISION_CHANGED":    "The Gateway's policy changed while this call was being checked. Run the request again.",
	"CAPABILITY":                 "The Gateway refused to run this call because an internal check failed. Run the request again; if it repeats, give the operator the correlation ID {correlationId}.",
	"RATE_LIMITED":               "Too many tool calls in a short time. Wait a minute and try again.",
	"QUEUE_FULL":                 "The Gateway is busy. Try again shortly.",
	"SESSION_INVALID":            "Your Gateway session is not valid. Sign in again.",
	"SESSION_STATE":              "Your Gateway session has ended. Sign in again.",
	"BACKEND_ERROR":              "The tool's server reported an error.",
	"DISPATCH_FAILED":            "The tool's server could not be started or reached. The operator can check it in the Servers view.",
	"CLIENT_DEADLINE":            "The tool did not finish in time.",
	"UPSTREAM_TIMEOUT":           "The tool's server stopped responding. It may have completed the action; check before trying again.",
	"INPUT_REQUIRED_UNSUPPORTED": "The tool asked for input that the Gateway does not relay.",
	"RESULT_INVALID":             "The tool's server returned a result the Gateway could not validate, so it was withheld.",
	"BACKEND_OUTPUT_INVALID":     "The tool's server sent data that is not valid MCP, so the call was stopped and the server restarted.",
	"INSTANCE_FAILED":            "The tool's server stopped while running this call. It may have completed the action; check before trying again.",
	"SCHEMA_INVALID":             "The arguments do not match what this tool accepts.",
}

// reasonAliases maps reason codes the Gateway emits under another name to
// the Table B.2 entry whose message applies.
var reasonAliases = map[string]string{
	ReasonCapability:   "CAPABILITY",
	ReasonSessionEnded: "SESSION_STATE",
	"FILTER_WITHHELD":  "FILTER_BLOCKED",
}

// extraMessages covers reason codes that Table B.2 does not list.
var extraMessages = map[string]string{
	ReasonListenLimit:   "This session already has the maximum number of open listen streams. Close one, then try again.",
	ReasonApprovalNoSvc: "This call needs approval, but the Gateway's approval service is not available. Ask the Gateway operator to approve the call or check `smcpctl health`, then run the same request again.",
	"APPROVAL_EXPIRED":  "The approval for this call expired before it was used. Run the same request again to ask for a new approval.",
	"APPROVAL_CONSUMED": "The approval for this call was already used by an identical call. Run the same request again to ask for a new approval.",
	"CANCELLED":         "The call was cancelled before it finished. It may have completed the action; check before trying again.",
}

// codeMessages is the fallback by error code for a reason code without its
// own message (for example a filter's reason code).
var codeMessages = map[int64]string{
	CodePolicyDenied:      "The Gateway's policy refused this call.",
	CodeApprovalRequired:  "This call needs approval. Open {approvalUrl} to approve it, then run the same request again.",
	CodeResponseWithheld:  "The tool's result was withheld by the Gateway. The operator can see why in the audit record {correlationId}.",
	CodeGatewayFailClosed: "The Gateway is not accepting tool calls right now because a safety check failed. The operator can see the cause with `smcpctl health`.",
	CodeRateLimited:       "Too many tool calls in a short time. Wait a minute and try again.",
	CodeSessionInvalid:    "Your Gateway session is not valid. Sign in again.",
	CodeBackendError:      "The tool's server reported an error.",
	CodeTimeout:           "The tool did not finish in time.",
	CodeIndeterminate:     "The call ended without a known outcome. It may have completed the action; check before trying again.",
	CodeInputRequired:     "The tool asked for input that the Gateway does not relay.",
}

// Message returns the plain-language data.message for an error (FR-1.51),
// with {approvalUrl} and {correlationId} filled from data.
func Message(code int64, reason string, data map[string]any) string {
	m, ok := reasonMessages[reason]
	if !ok {
		if a, ok2 := reasonAliases[reason]; ok2 {
			m, ok = reasonMessages[a]
		}
	}
	if !ok {
		m, ok = extraMessages[reason]
	}
	if !ok {
		m = codeMessages[code]
	}
	url := fmt.Sprint(data["approvalUrl"])
	if data["approvalUrl"] == nil {
		url = "the Gateway console's Approvals view"
	}
	return strings.NewReplacer("{approvalUrl}", url, "{correlationId}", fmt.Sprint(data["correlationId"])).Replace(m)
}
