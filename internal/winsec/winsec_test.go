package winsec

import (
	"errors"
	"runtime"
	"testing"
)

func TestEvaluate(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	own := OwnerEntries(user)
	if err := Evaluate(`C:\s`, true, false, own, true, user, SIDSystem, SIDAdministrators); err != nil {
		t.Fatalf("owner entries refused: %v", err)
	}
	// A deny entry for another SID never makes the object less private.
	deny := append(append([]Entry(nil), own...), Entry{SID: SIDNetwork, Access: FullControl, Deny: true})
	if err := Evaluate(`C:\s`, true, false, deny, true, user, SIDSystem, SIDAdministrators); err != nil {
		t.Fatalf("deny entry refused: %v", err)
	}
	cases := []struct {
		name      string
		protected bool
		null      bool
		entries   []Entry
		want      func(*ACLError) bool
	}{
		{"users group", true, false, append(append([]Entry(nil), own...), Entry{SID: SIDUsers, Access: Read}),
			func(e *ACLError) bool { return len(e.Foreign) == 1 && e.Foreign[0].SID == SIDUsers }},
		{"inherited", false, false, own, func(e *ACLError) bool { return e.Inherited }},
		{"null DACL", true, true, nil, func(e *ACLError) bool { return e.Null }},
		{"unknown ACE type", true, false, []Entry{{SID: "(ACE type 9)", Access: Read}},
			func(e *ACLError) bool { return len(e.Foreign) == 1 }},
	}
	for _, c := range cases {
		err := Evaluate(`C:\s`, c.protected, c.null, c.entries, true, user, SIDSystem, SIDAdministrators)
		var ae *ACLError
		if !errors.As(err, &ae) || !errors.Is(err, ErrForeignAccess) || !c.want(ae) {
			t.Errorf("%s: Evaluate = %v", c.name, err)
		}
	}
	// A file below a protected directory inherits; it is not required to be
	// protected itself.
	if err := Evaluate(`C:\s\f`, false, false, own, false, user, SIDSystem, SIDAdministrators); err != nil {
		t.Fatalf("inherited file refused: %v", err)
	}
}

func TestIsProtectedBlob(t *testing.T) {
	b := append(append([]byte(nil), dpapiHeader...), 0x01)
	if !IsProtectedBlob(b) {
		t.Fatal("DPAPI header not recognized")
	}
	for _, s := range [][]byte{nil, dpapiHeader, []byte("-----BEGIN EC PRIVATE KEY-----\n"), []byte("0123456789abcdef0123456789abcdef\n")} {
		if IsProtectedBlob(s) {
			t.Fatalf("IsProtectedBlob(%q) = true", s)
		}
	}
}

func TestOtherPlatformsReturnErrNotWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has the real implementation")
	}
	if _, err := Protect([]byte("x")); !errors.Is(err, ErrNotWindows) {
		t.Fatalf("Protect = %v", err)
	}
	if err := CheckDACL(t.TempDir(), true); !errors.Is(err, ErrNotWindows) {
		t.Fatalf("CheckDACL = %v", err)
	}
}
