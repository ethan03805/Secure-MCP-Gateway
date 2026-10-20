//go:build windows

package backup

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// secureRestored gives the extracted state directory, which inherited the
// DACL of its parent, the protected DACL that the state check requires
// (FR-21.5): the DACL of the state directory it replaces, so a machine-mode
// state keeps its service-account entries, or the per-user CP-46 DACL of
// the account running the restore when there is none.
func secureRestored(restored, current string) error {
	if exists(current) {
		protected, null, entries, err := winsec.DACL(current)
		if err == nil && protected && !null && len(entries) > 0 {
			return winsec.SetProtectedDACL(restored, entries)
		}
	}
	return keys.SecureStateDir(restored)
}
