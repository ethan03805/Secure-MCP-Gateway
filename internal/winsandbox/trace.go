package winsandbox

import "strings"

// ProcessRecord is one process created inside a traced job
// (ProcessTrace, Windows only).
type ProcessRecord struct {
	PID       uint32 `json:"pid"`
	ParentPID uint32 `json:"parent_pid"`
	// Image is the full path of the executable, or "" when the process
	// ended before it could be opened.
	Image string `json:"image"`
}

// InterpreterStartedBy returns the records of command interpreters
// (cmd.exe, powershell.exe, pwsh.exe, a .bat or .cmd file, as CheckCommand
// recognizes them) whose parent process has the image base name parent,
// compared case-insensitively, such as "smcpd.exe" (SR-4.8-2).
func InterpreterStartedBy(recs []ProcessRecord, parent string) []ProcessRecord {
	parents := map[uint32]bool{}
	for _, r := range recs {
		if r.Image != "" && strings.EqualFold(baseName(r.Image), parent) {
			parents[r.PID] = true
		}
	}
	var out []ProcessRecord
	for _, r := range recs {
		if parents[r.ParentPID] && r.Image != "" && CheckCommand(r.Image) != nil {
			out = append(out, r)
		}
	}
	return out
}

// baseName is the last element of a Windows or POSIX path.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
