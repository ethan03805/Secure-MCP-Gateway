package winsandbox

import (
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestContextForgeUnconfinedCheck(t *testing.T) {
	on := false
	c := ContextForgeUnconfinedCheck(func() bool { return on })
	if cs := c(time.Now()); cs != nil {
		t.Fatalf("not running: %+v", cs)
	}
	on = true
	if cs := c(time.Now()); len(cs) != 1 || cs[0].Name != "contextforge_unconfined" || cs[0].Critical {
		t.Fatalf("running: %+v", cs)
	}
	if cs := ContextForgeUnconfinedCheck(nil)(time.Now()); cs != nil {
		t.Fatalf("nil: %+v", cs)
	}
	if runtime.GOOS != "windows" {
		if _, err := StartManaged(ManagedSpec{Path: "/bin/true"}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("StartManaged off Windows: %v", err)
		}
	}
}
