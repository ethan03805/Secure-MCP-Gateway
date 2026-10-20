package winsandbox

import (
	"crypto/sha256"
	"encoding/hex"
)

// ProfileName is the AppContainer profile name of one enabled server
// revision (FR-21.13): "smcp-" and the first 40 hexadecimal digits of the
// SHA-256 of "serverID@revision". It is stable, so the profile and the SID
// derived from it are the same at enablement, at every start and at
// disable, and it fits the 64-character limit of profile names.
func ProfileName(serverID, revision string) string {
	h := sha256.Sum256([]byte(serverID + "@" + revision))
	return "smcp-" + hex.EncodeToString(h[:])[:40]
}

// ProfileDisplayName is the profile's display name.
func ProfileDisplayName(serverID, revision string) string {
	return "Secure MCP Gateway server " + serverID + "@" + revision
}
