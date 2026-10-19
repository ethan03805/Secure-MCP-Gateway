//go:build windows

package health

import (
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsFreeSpaceMeasured: the free space of the volume is measured
// on Windows, so the Disk check reports a level instead of "free space
// unknown" (FR-21.26). Partial: the smcpd start with the quota test hook
// is not run here.
func TestWindowsFreeSpaceMeasured(t *testing.T) {
	reqtest.Partial(t, "FR-21.26")
	dir := t.TempDir()
	free, err := FreeBytes(dir)
	if err != nil || free == 0 {
		t.Fatalf("FreeBytes = %d, %v", free, err)
	}
	for _, c := range Disk(dir)(time.Now()) {
		if strings.Contains(c.Detail, "unknown") {
			t.Fatalf("free space not measured: %+v", c)
		}
	}
}
