//go:build windows

package wintest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

var (
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	userenv                 = windows.NewLazySystemDLL("userenv.dll")
	procLogonUserW          = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOn = advapi32.NewProc("ImpersonateLoggedOnUser")
	procLoadUserProfileW    = userenv.NewProc("LoadUserProfileW")
	procUnloadUserProfile   = userenv.NewProc("UnloadUserProfile")
	procDeleteProfileW      = userenv.NewProc("DeleteProfileW")
)

const (
	logon32LogonInteractive = 2
	logon32ProviderDefault  = 0
	piNoUI                  = 1
)

// profileInfo is PROFILEINFOW.
type profileInfo struct {
	size        uint32
	flags       uint32
	userName    *uint16
	profilePath *uint16
	defaultPath *uint16
	serverName  *uint16
	policyPath  *uint16
	profile     windows.Handle
}

// User is a local standard account created for a test.
type User struct {
	Name, Password, SID string
	token               windows.Token
}

func requireAdmin(t testing.TB) {
	t.Helper()
	if !winsec.IsElevated() {
		t.Skip("creating a local account needs an elevated process (the hosted Windows runner is one)")
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func run(t testing.TB, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		// The command line holds a test password; print only the verb.
		t.Fatalf("%s %s: %v: %s", args[0], args[1], err, strings.TrimSpace(string(out)))
	}
}

// NewGroup creates a local group and deletes it when the test ends.
func NewGroup(t testing.TB) (name, sid string) {
	t.Helper()
	requireAdmin(t)
	name = "smcpg" + randomHex(5)
	run(t, "net", "localgroup", name, "/add")
	t.Cleanup(func() { _ = exec.Command("net", "localgroup", name, "/delete").Run() })
	sid, err := winsec.LookupSID(name)
	if err != nil {
		t.Fatal(err)
	}
	return name, sid
}

// NewUser creates a local standard user (a member of Users only, plus the
// given local groups), logs it on interactively with its profile loaded,
// and deletes the profile and the account when the test ends.
func NewUser(t testing.TB, groups ...string) *User {
	t.Helper()
	requireAdmin(t)
	u := &User{Name: "smcpu" + randomHex(5), Password: "Aa1!" + randomHex(12)}
	run(t, "net", "user", u.Name, u.Password, "/add", "/passwordchg:no", "/expires:never")
	t.Cleanup(func() { _ = exec.Command("net", "user", u.Name, "/delete").Run() })
	for _, g := range groups {
		run(t, "net", "localgroup", g, u.Name, "/add")
	}
	sid, err := winsec.LookupSID(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	u.SID = sid
	name, _ := windows.UTF16PtrFromString(u.Name)
	dom, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(u.Password)
	r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(dom)), uintptr(unsafe.Pointer(pw)),
		logon32LogonInteractive, logon32ProviderDefault, uintptr(unsafe.Pointer(&u.token)))
	if r == 0 {
		t.Fatalf("LogonUser %s: %v", u.Name, e)
	}
	t.Cleanup(func() { u.token.Close() })
	// DPAPI needs the user's profile (its master keys live there).
	// LoadUserProfile needs the backup and restore privileges enabled.
	enablePrivileges(t, "SeBackupPrivilege", "SeRestorePrivilege")
	pi := profileInfo{flags: piNoUI, userName: name}
	pi.size = uint32(unsafe.Sizeof(pi))
	if r, _, e := procLoadUserProfileW.Call(uintptr(u.token), uintptr(unsafe.Pointer(&pi))); r == 0 {
		t.Fatalf("LoadUserProfile %s: %v", u.Name, e)
	}
	t.Cleanup(func() {
		_, _, _ = procUnloadUserProfile.Call(uintptr(u.token), uintptr(pi.profile))
		sidp, _ := windows.UTF16PtrFromString(u.SID)
		_, _, _ = procDeleteProfileW.Call(uintptr(unsafe.Pointer(sidp)), 0, 0)
	})
	return u
}

func enablePrivileges(t testing.TB, names ...string) {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	for _, n := range names {
		var luid windows.LUID
		np, _ := windows.UTF16PtrFromString(n)
		if err := windows.LookupPrivilegeValue(nil, np, &luid); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			t.Fatalf("enable %s: %v", n, err)
		}
	}
}

// As runs f on a locked OS thread that impersonates the user: file, pipe
// and DPAPI calls in f are made with the user's token.
func (u *User) As(t testing.TB, f func()) {
	t.Helper()
	done := make(chan struct{})
	var failure string
	go func() {
		defer close(done)
		runtime.LockOSThread()
		// The thread is not unlocked: if RevertToSelf failed it must not
		// run other goroutines with the user's token, so it ends with
		// this goroutine.
		if r, _, e := procImpersonateLoggedOn.Call(uintptr(u.token)); r == 0 {
			failure = fmt.Sprintf("ImpersonateLoggedOnUser %s: %v", u.Name, e)
			return
		}
		defer func() {
			if err := windows.RevertToSelf(); err != nil {
				failure = "RevertToSelf: " + err.Error()
			}
		}()
		f()
	}()
	<-done
	if failure != "" {
		t.Fatal(failure)
	}
}
