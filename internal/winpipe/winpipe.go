// Package winpipe is the Windows named-pipe transport of the Harness
// Interface Endpoint (SRS FR-21.8, FR-21.9, SR-2.8-6, CP-02).
//
// Listen creates the pipe with FILE_FLAG_FIRST_PIPE_INSTANCE, so that it
// fails when another process created the name first (a squatted pipe,
// health cause pipe_squatted), with PIPE_REJECT_REMOTE_CLIENTS, and with
// a protected DACL that grants read and write to the account running the
// Gateway and to the harness clients, denies NETWORK and ANONYMOUS LOGON,
// and grants no other SID. Clients get read and write without
// FILE_CREATE_PIPE_INSTANCE, so that no client can add a server instance
// of the pipe. Each accepted Conn carries the user SID of the client's
// token, read by impersonating the client at identification level
// (ImpersonateNamedPipeClient, then OpenThreadToken), never from a
// process ID.
//
// The Windows implementation is in winpipe_windows.go; elsewhere every
// function returns ErrNotWindows.
package winpipe

import (
	"errors"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// ErrNotWindows is returned off Windows.
var ErrNotWindows = errors.New("winpipe: named pipes are only available on Windows")

// ErrSquatted is returned by Listen when the pipe name already exists: a
// process created it before the Gateway (SR-2.8-6, cause pipe_squatted).
var ErrSquatted = errors.New("pipe_squatted: the harness pipe already exists, created by another process; refusing to serve it")

// Name is the CP-02 pipe name: \\.\pipe\smcp-harness in the machine mode,
// \\.\pipe\smcp-harness-<user SID> in the per-user mode.
func Name(perUserSID string) string {
	if perUserSID == "" {
		return `\\.\pipe\smcp-harness`
	}
	return `\\.\pipe\smcp-harness-` + perUserSID
}

// Access masks of the pipe DACL. A client may read and write but not
// create pipe instances (FILE_CREATE_PIPE_INSTANCE is FILE_APPEND_DATA).
const (
	serverAccess = winsec.ReadWrite
	clientAccess = winsec.ReadWrite &^ 0x4
)

// Entries is the SR-2.8-6 DACL of the pipe: the server account (which
// may also create instances), each client SID, and deny entries for
// NETWORK and ANONYMOUS LOGON. A client SID equal to the server's is
// listed once.
func Entries(serverSID string, clientSIDs ...string) []winsec.Entry {
	out := []winsec.Entry{
		{SID: winsec.SIDNetwork, Access: winsec.FullControl, Deny: true},
		{SID: winsec.SIDAnonymous, Access: winsec.FullControl, Deny: true},
		{SID: serverSID, Access: serverAccess},
	}
	seen := map[string]bool{serverSID: true}
	for _, s := range clientSIDs {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, winsec.Entry{SID: s, Access: clientAccess})
	}
	return out
}
