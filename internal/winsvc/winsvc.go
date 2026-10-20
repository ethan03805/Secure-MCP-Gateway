// Package winsvc holds the Windows service plumbing shared by smcpd and
// smcpctl (SRS FR-21.1, FR-21.6, FR-21.7): the supported Windows builds,
// the per-user Task Scheduler task and its Run-key fallback, the named
// stop event through which smcpctl asks a per-user smcpd for an orderly
// stop, and the supervisor that restarts a failed per-user smcpd.
//
// The portable parts (the version rule, the task definition, the event
// name) are plain functions tested on every platform; the parts that call
// Windows are in winsvc_windows.go, with stubs elsewhere.
package winsvc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// ErrNotWindows is returned by the Windows-only functions elsewhere.
var ErrNotWindows = errors.New("winsvc: only available on Windows")

// TaskName is the per-user Task Scheduler task (FR-21.6).
const TaskName = "smcp-gateway"

// RunValue is the HKCU\Software\Microsoft\Windows\CurrentVersion\Run value
// of the fallback when Windows refuses the task to the user.
const RunValue = "smcp-gateway"

// ServiceName is the machine-mode Windows service, run as NT SERVICE\smcpd.
const ServiceName = "smcpd"

// Version is the part of RtlGetVersion that FR-21.1 reads.
type Version struct {
	Major, Minor, Build uint32
	// Server is true for Windows Server (ProductType is not
	// VER_NT_WORKSTATION).
	Server bool
}

func (v Version) String() string {
	kind := "Windows"
	if v.Server {
		kind = "Windows Server"
	}
	return fmt.Sprintf("%s %d.%d build %d", kind, v.Major, v.Minor, v.Build)
}

// Minimum builds of FR-21.1: Windows 11 23H2 (22631) on clients, Windows
// Server 2022 (20348) on servers. Windows Server 2025 is build 26100.
const (
	MinClientBuild = 22631
	MinServerBuild = 20348
)

// CheckVersion refuses a Windows build older than FR-21.1 allows, naming
// the build found and the minimum.
func CheckVersion(v Version) error {
	minBuild, name := uint32(MinClientBuild), "Windows 11 version 23H2 (build 22631)"
	if v.Server {
		minBuild, name = MinServerBuild, "Windows Server 2022 (build 20348)"
	}
	if v.Major < 10 || v.Build < minBuild {
		return fmt.Errorf("%s is not supported: the Gateway needs %s or later", v, name)
	}
	return nil
}

// StopEventName is the session-local named event a per-user smcpd started
// with configuration cfgPath waits on; setting it asks for an orderly stop
// (FR-21.7). The name depends on the absolute configuration path, so two
// installations of one user do not stop each other.
func StopEventName(cfgPath string) string {
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		abs = cfgPath
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(abs))))
	return `Local\smcp-gateway-stop-` + hex.EncodeToString(sum[:8])
}

// TaskXML is the Task Scheduler definition of the per-user installation
// (FR-21.6): a logon trigger for the installing user's SID only, run as
// that user with the least privilege, no time limit, and one instance at a
// time. smcpd's own -supervise mode restarts a failed Gateway: the task
// scheduler's RestartOnFailure covers only a task that fails to start, so
// the definition sets it as well. The result is UTF-8; TaskFile encodes it
// for schtasks /xml.
func TaskXML(userSID, smcpd, cfgPath, workDir string) ([]byte, error) {
	if userSID == "" || smcpd == "" || cfgPath == "" {
		return nil, errors.New("winsvc: task needs a user SID, the smcpd path and the configuration path")
	}
	esc := func(v string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(v))
		return b.String()
	}
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Secure MCP Gateway, per-user installation (not enforced). Written by smcpctl install.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>%[1]s</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%[1]s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%[2]s</Command>
      <Arguments>%[3]s</Arguments>
      <WorkingDirectory>%[4]s</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`, esc(userSID), esc(smcpd), esc(CommandLine("-supervise", "-config", cfgPath)), esc(workDir)), nil
}

// TaskFile encodes a task definition as schtasks /xml reads it: UTF-16
// little endian with a byte order mark.
func TaskFile(utf8XML []byte) []byte {
	u := utf16.Encode([]rune(string(utf8XML)))
	out := make([]byte, 2, 2+2*len(u))
	out[0], out[1] = 0xff, 0xfe
	for _, c := range u {
		out = append(out, byte(c&0xff), byte(c>>8)) //nolint:gosec // the two bytes of a UTF-16 code unit
	}
	return out
}

// CommandLine joins arguments by the Microsoft C runtime quoting rules
// (the rules CommandLineToArgvW and Go's os.Args parsing use), so that a
// path with spaces or quotes reaches the program unchanged.
func CommandLine(args ...string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = quoteArg(a)
	}
	return strings.Join(out, " ")
}

// ImageOf returns the program of a service command line: the first
// argument as CommandLineToArgvW reads it (quoted or up to the first
// blank). Backslashes in a quoted program path are literal, as Windows
// takes them for the program name.
func ImageOf(commandLine string) string {
	s := strings.TrimLeft(commandLine, " \t")
	if strings.HasPrefix(s, `"`) {
		if i := strings.IndexByte(s[1:], '"'); i >= 0 {
			return s[1 : i+1]
		}
		return s[1:]
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

func quoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\v\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			slashes++
			continue
		case '"':
			b.WriteString(strings.Repeat(`\`, 2*slashes+1))
			b.WriteByte('"')
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
			b.WriteByte(c)
		}
		slashes = 0
	}
	b.WriteString(strings.Repeat(`\`, 2*slashes))
	b.WriteByte('"')
	return b.String()
}
