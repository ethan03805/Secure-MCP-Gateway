//go:build !windows

package wintest

import "testing"

// User is a local account created for a test.
type User struct{ Name, Password, SID string }

// NewUser skips the test off Windows.
func NewUser(t testing.TB, groups ...string) *User {
	t.Helper()
	t.Skip("a second Windows account needs Windows")
	return nil
}

// NewGroup skips the test off Windows.
func NewGroup(t testing.TB) (name, sid string) {
	t.Helper()
	t.Skip("a Windows local group needs Windows")
	return "", ""
}

// As skips the test off Windows.
func (u *User) As(t testing.TB, f func()) {
	t.Helper()
	t.Skip("impersonation needs Windows")
}
