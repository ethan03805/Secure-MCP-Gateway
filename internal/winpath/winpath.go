// Package winpath holds the Windows path rules of SRS FR-21.25 as plain
// string functions, so that they are tested on every platform: which
// paths are absolute (a drive letter or a leading separator, never joined
// to the working directory), which are refused (alternate data streams,
// reserved device names, `\\?\` and `\\.\` device prefixes, UNC hosts and
// drive-relative forms such as `C:x`), and case-insensitive containment.
//
// The Server Runtime Manager (filesystem slots and grants) and the Request
// Inspection Pipeline (path rules and path arguments) apply them on
// Windows; on Linux and macOS they are not called.
package winpath

import (
	"strings"
)

// Reasons a path is refused, as Refused returns them.
const (
	RuleStream        = "windows-stream"         // an alternate data stream (name:stream)
	RuleDeviceName    = "windows-device-name"    // CON, PRN, AUX, NUL, COM1-9, LPT1-9
	RuleDevicePrefix  = "windows-device-prefix"  // \\?\, \\.\ or \??\
	RuleUNC           = "windows-unc"            // \\host\share
	RuleDriveRelative = "windows-drive-relative" // C:x, relative to the drive's current directory
)

func isSep(c byte) bool { return c == '\\' || c == '/' }

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// hasDrive reports whether p starts with a drive letter and a colon.
func hasDrive(p string) bool { return len(p) >= 2 && isLetter(p[0]) && p[1] == ':' }

// IsAbs reports whether p is absolute under FR-21.25: a drive letter
// followed by a separator (`C:\x`, `C:/x`) or a leading separator (`\x`,
// `/x`, rooted on the current drive). UNC and device paths also start with
// a separator; Refused refuses them.
func IsAbs(p string) bool {
	if hasDrive(p) {
		return len(p) >= 3 && isSep(p[2])
	}
	return len(p) > 0 && isSep(p[0])
}

var reserved = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true}

func init() {
	for _, d := range "123456789" {
		reserved["COM"+string(d)] = true
		reserved["LPT"+string(d)] = true
	}
}

// Refused returns the FR-21.25 rule that p breaks, or "".
func Refused(p string) string {
	if len(p) >= 4 && isSep(p[0]) && isSep(p[1]) && (p[2] == '?' || p[2] == '.') && isSep(p[3]) {
		return RuleDevicePrefix
	}
	if len(p) >= 4 && isSep(p[0]) && p[1] == '?' && p[2] == '?' && isSep(p[3]) {
		return RuleDevicePrefix
	}
	if len(p) >= 2 && isSep(p[0]) && isSep(p[1]) {
		return RuleUNC
	}
	rest := p
	if hasDrive(p) {
		if len(p) == 2 || !isSep(p[2]) {
			return RuleDriveRelative
		}
		rest = p[2:]
	}
	if strings.Contains(rest, ":") {
		return RuleStream
	}
	for _, comp := range strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' || r == '/' }) {
		base := comp
		if i := strings.IndexByte(base, '.'); i >= 0 {
			base = base[:i]
		}
		base = strings.TrimRight(base, " ")
		if reserved[strings.ToUpper(base)] {
			return RuleDeviceName
		}
	}
	return ""
}

// normalize turns separators into backslashes and drops a trailing one,
// except after a drive root.
func normalize(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	for len(p) > 1 && strings.HasSuffix(p, `\`) && !(len(p) == 3 && hasDrive(p)) {
		p = p[:len(p)-1]
	}
	return p
}

// Within reports whether p is root or lies below it, comparing as Windows
// does: case-insensitively, with either separator. Both paths must already
// be resolved (final paths).
func Within(p, root string) bool {
	p, root = normalize(p), normalize(root)
	if strings.EqualFold(p, root) {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, `\`) {
		prefix += `\`
	}
	return len(p) > len(prefix) && strings.EqualFold(p[:len(prefix)], prefix)
}
