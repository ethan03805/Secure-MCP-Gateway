package ops

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestStateProtectionCauses: on Windows the running Gateway repeats the
// state-directory check, and a foreign DACL entry is the critical cause
// state_acl (FR-21.5), an undecryptable key the critical cause
// key_protection (FR-21.10). Partial: the check against a real DACL is
// internal/keys TestWindowsKeyProtection; the monitor's fail-closed latch
// is internal/health.
func TestStateProtectionCauses(t *testing.T) {
	reqtest.Partial(t, "FR-21.5", "FR-21.10")
	var err error
	c := stateProtection(func() error { return err })
	if got := c(time.Now()); len(got) != 0 {
		t.Fatalf("clean: %v", got)
	}
	for _, tc := range []struct {
		want string
		err  error
	}{
		{health.CauseStateACL, fmt.Errorf("%w: C:\\state grants S-1-5-32-545", keys.ErrStateACL)},
		{health.CauseKeyProtection, fmt.Errorf("%w: keys\\evidence.key", keys.ErrKeyProtection)},
		{health.CauseStateACL, errors.New("read DACL: access denied")},
	} {
		want, e := tc.want, tc.err
		err = e
		got := c(time.Now())
		if len(got) != 1 || got[0].Name != want || !got[0].Critical {
			t.Errorf("%v: %+v, want critical %s", e, got, want)
		}
	}
}
