// Package pipeline defines the extension points of the enforcement pipeline
// (FR-4.3) that later elements plug into, each with a default
// implementation that preserves the Gateway's current behavior:
//
//	Approver        E-07 Approval Service       default RefuseApprover (-31002)
//	RequestFilter   E-09 Request Inspection     default chain: schema-validate
//	ResponseFilter  E-11 Response Inspection    default chain: empty
//	Launcher        E-15/E-16 Runtime, Sandbox  default SubprocessLauncher (unconfined); internal/sandbox is the confining one
//	ManifestSource  E-13/E-14 Trust, Registry   default LiveManifest (unverified)
//	SecretBroker    E-20 Secret Broker          default NoSecrets
//	Capabilities    E-12 -> E-10 launch caps    concrete one-use ledger
//
// The package depends only on the policy and MCP SDK types, so elements can
// implement these interfaces without importing the edge or backend
// packages. internal/README.md maps each seam to the element and agent that
// fills it.
package pipeline

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// Call is what every stage knows about one tools/call after the decision.
// Stages must treat it as read-only, except RequireApproval and
// ApprovalReason.
type Call struct {
	CorrelationID  string
	SessionID      string
	PrincipalID    string
	Template       string
	Purpose        string
	Project        string
	EndUser        string
	Server         string // server alias
	Tool           string // backend tool name
	PublicName     string
	ServerRevision string
	ToolRevision   string
	ManifestSource string // "live" (unverified) or the verified manifest source
	DecisionID     string
	PolicyRevision string
	Obligations    policy.Obligations
	DecisiveRules  []string // rule IDs that decided the permit (FR-3.18)
	InputSchema    any
	OutputSchema   any
	// Inspection collects the filter runs of this call across both chains
	// (findings, tags, timing). RunRequest and RunResponse create it when
	// nil; later stages read it through its methods.
	Inspection *Inspection
	// RequireApproval may be set by a request filter to require approval
	// (E-07) although the decision did not. It can only add the obligation
	// (restrict-only, SR-1.12-2); the Anomaly Scorer's synchronous
	// obligation (E-31, FR-4.15) uses it. ApprovalReason names the cause.
	RequireApproval bool
	ApprovalReason  string
}
