//go:build windows

package winsec

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestWindowsProtectedDACL(t *testing.T) {
	reqtest.Partial(t, "FR-21.5")
	user, err := ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A fresh directory under %TEMP% inherits its parent's DACL.
	if err := CheckDACL(dir, true, user, SIDSystem, SIDAdministrators); err == nil {
		t.Fatal("inherited DACL accepted")
	}
	if err := SetProtectedDACL(dir, OwnerEntries(user)); err != nil {
		t.Fatal(err)
	}
	protected, null, entries, err := DACL(dir)
	if err != nil || !protected || null {
		t.Fatalf("DACL = %v %v %v", protected, null, err)
	}
	var sids []string
	for _, e := range entries {
		sids = append(sids, e.SID)
	}
	slices.Sort(sids)
	want := []string{user, SIDSystem, SIDAdministrators}
	slices.Sort(want)
	if !slices.Equal(sids, want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	if err := CheckDACL(dir, true, user, SIDSystem, SIDAdministrators); err != nil {
		t.Fatalf("CheckDACL after SetProtectedDACL: %v", err)
	}
	// A file created below inherits exactly these entries.
	f := filepath.Join(dir, "key")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckDACL(f, false, user, SIDSystem, SIDAdministrators); err != nil {
		t.Fatalf("file below: %v", err)
	}
	// FR-21.5: an entry for Users is a foreign grant.
	if err := Grant(dir, SIDUsers, Read); err != nil {
		t.Fatal(err)
	}
	err = CheckDACL(dir, true, user, SIDSystem, SIDAdministrators)
	var ae *ACLError
	if !errors.As(err, &ae) || len(ae.Foreign) != 1 || ae.Foreign[0].SID != SIDUsers || ae.Inherited {
		t.Fatalf("after granting Users: %v", err)
	}
	if err := CheckDACL(f, false, user, SIDSystem, SIDAdministrators); err == nil {
		t.Fatal("file below did not inherit the Users entry")
	}
	if err := Revoke(dir, SIDUsers); err != nil {
		t.Fatal(err)
	}
	if err := CheckDACL(dir, true, user, SIDSystem, SIDAdministrators); err != nil {
		t.Fatalf("after Revoke: %v", err)
	}
}

func TestWindowsDPAPIRoundTrip(t *testing.T) {
	reqtest.Partial(t, "FR-21.10", "SR-2.13-4")
	secret := []byte("-----BEGIN EC PRIVATE KEY-----\nexample\n-----END EC PRIVATE KEY-----\n")
	b, err := Protect(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !IsProtectedBlob(b) || bytes.Contains(b, []byte("example")) {
		t.Fatalf("Protect output is not an opaque DPAPI blob: % x", b[:24])
	}
	got, err := Unprotect(b)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Unprotect = %q, %v", got, err)
	}
	// A damaged blob is refused, never returned.
	bad := slices.Clone(b)
	bad[len(bad)-1] ^= 0xff
	if _, err := Unprotect(bad); !errors.Is(err, ErrUnprotect) {
		t.Fatalf("damaged blob: %v", err)
	}
	if _, err := Unprotect(secret); !errors.Is(err, ErrUnprotect) {
		t.Fatalf("plaintext: %v", err)
	}
	if e, err := Protect(nil); err != nil || !IsProtectedBlob(e) {
		t.Fatalf("empty: %v", err)
	}
}

func TestWindowsFreeBytesAndReplace(t *testing.T) {
	reqtest.Partial(t, "FR-21.26", "FR-21.23")
	dir := t.TempDir()
	free, err := FreeBytes(dir)
	if err != nil || free == 0 {
		t.Fatalf("FreeBytes = %d, %v", free, err)
	}
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(a, b); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(b); string(got) != "new" {
		t.Fatalf("b = %q", got)
	}
	if _, err := os.Stat(a); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a still exists: %v", err)
	}
}

func TestWindowsSecurityAttributes(t *testing.T) {
	user, err := ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := SecurityAttributes(append(OwnerEntries(user), Entry{SID: SIDNetwork, Access: FullControl, Deny: true}))
	if err != nil {
		t.Fatal(err)
	}
	protected, null, entries, err := readDescriptor(sa.SecurityDescriptor)
	if err != nil || !protected || null || len(entries) != 4 || !entries[0].Deny || entries[0].SID != SIDNetwork {
		t.Fatalf("descriptor = %v %v %v %v", protected, null, entries, err)
	}
}
