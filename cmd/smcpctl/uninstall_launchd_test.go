package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestUnloadLaunchdWaitsForRemoval: uninstall boots the agent out and
// returns only once launchd no longer knows it, as launchd removes a
// booted-out service asynchronously; it reports an agent that stays.
func TestUnloadLaunchdWaitsForRemoval(t *testing.T) {
	const target = "gui/501/com.smcp.gateway"
	fake := func(loadedFor int) (func(argv ...string) error, *[]string) {
		var calls []string
		prints := 0
		return func(argv ...string) error {
			calls = append(calls, strings.Join(argv, " "))
			if argv[1] == "print" {
				prints++
				if loadedFor < 0 || prints <= loadedFor {
					return nil // still known to launchd
				}
				return errors.New("Could not find service")
			}
			return nil
		}, &calls
	}

	run, calls := fake(3)
	if err := unloadLaunchd(run, target, 5*time.Second, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	want := []string{"launchctl bootout " + target, "launchctl print " + target, "launchctl print " + target, "launchctl print " + target, "launchctl print " + target}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(*calls, "\n"), strings.Join(want, "\n"))
	}

	run, calls = fake(0) // not loaded: one bootout, one print
	if err := unloadLaunchd(run, target, 5*time.Second, time.Millisecond); err != nil || len(*calls) != 2 {
		t.Fatalf("not loaded: %v %v", err, *calls)
	}

	run, _ = fake(-1) // never removed
	err := unloadLaunchd(run, target, 50*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "still loaded") {
		t.Fatalf("an agent that stays loaded: %v", err)
	}
}
