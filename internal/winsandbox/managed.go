package winsandbox

import "io"

// CauseContextForgeUnconfined is the health cause the Health & Safety
// Monitor reports while the bundled ContextForge instance runs outside the
// Enforced profile (FR-22.25). On Windows that is always the case, in every
// installation mode: the instance runs in its own Job Object and not in an
// AppContainer (FR-21, "Relation to FR-20 and FR-22").
const CauseContextForgeUnconfined = "contextforge_unconfined"

// ManagedSpec describes a long-running process the Gateway manages, such as
// the bundled ContextForge instance (FR-22.25): not an MCP stdio backend,
// so its standard input is empty and its output goes to the given writers.
type ManagedSpec struct {
	// Path is the absolute path of the executable (for ContextForge, the
	// Python interpreter of its private virtual environment).
	Path string
	Args []string
	// Env is the complete environment as KEY=value strings (SR-2.14-1).
	Env []string
	// Dir is the private working directory.
	Dir string
	// Stdout and Stderr receive the process's output; nil discards it.
	Stdout, Stderr io.Writer
	// Limits are the Job Object limits (CP-24).
	Limits Limits
}
