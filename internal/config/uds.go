package config

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// UDS configures the optional UDS Harness Profile (CP-02, FR-1.47,
// FR-2.15, SR-2.8-3): MCP as newline-delimited JSON-RPC over a
// Unix-domain socket for harnesses on the same host. A connection is
// accepted only from a registered peer UID that also presents the bearer
// key registered for it.
type UDS struct {
	Enabled bool `toml:"enabled" json:"enabled"`
	// Path is the socket path (CP-02 default /run/smcp/harness.sock).
	Path string `toml:"path" json:"path"`
	// Group owns the socket, which is created with mode 0660
	// (SR-2.8-3; default smcp-harness).
	Group string    `toml:"group" json:"group"`
	Peers []UDSPeer `toml:"peer" json:"peer"`
}

// UDSPeer registers one local user ID for a principal (FR-2.15). On
// Windows the peer is the user SID of the client's token on the named
// pipe (FR-21.9) and UID is not used.
type UDSPeer struct {
	UID       int    `toml:"uid" json:"uid"`
	SID       string `toml:"sid" json:"sid,omitempty"`
	Principal string `toml:"principal" json:"principal"`
	// KeyHash is the Argon2id hash of the principal's bearer key on the
	// socket (smcpctl hash-password produces one).
	KeyHash string `toml:"key_hash" json:"key_hash"`
	// Template is the Session Allow Policy Template of the sessions this
	// peer creates; empty means the profile's default template.
	Template string `toml:"template" json:"template"`
}

// CP-02 UDS defaults.
const (
	DefaultUDSPath  = "/run/smcp/harness.sock"
	DefaultUDSGroup = "smcp-harness"
)

// applyDefaults fills CP-02 defaults; Load resolves a relative path
// against the configuration directory. On Windows the default is the
// per-user named pipe \\.\pipe\smcp-harness-<user SID> (FR-21.8).
func (u *UDS) applyDefaults() {
	if u.Path == "" {
		u.Path = DefaultUDSPath
		if runtime.GOOS == "windows" {
			if sid, err := winsec.ProcessUserSID(); err == nil {
				u.Path = `\\.\pipe\smcp-harness-` + sid
			}
		}
	}
	if u.Group == "" {
		u.Group = DefaultUDSGroup
	}
}

// PeerSID returns the peer registered for a Windows user SID.
func (u *UDS) PeerSID(sid string) (UDSPeer, bool) {
	for _, p := range u.Peers {
		if p.SID != "" && strings.EqualFold(p.SID, sid) {
			return p, true
		}
	}
	return UDSPeer{}, false
}

// Peer returns the peer registered for uid.
func (u *UDS) Peer(uid int) (UDSPeer, bool) {
	for _, p := range u.Peers {
		if p.UID == uid {
			return p, true
		}
	}
	return UDSPeer{}, false
}

func (c *Config) checkUDS() error {
	u := c.UDS
	if !u.Enabled {
		return nil
	}
	if len(u.Peers) == 0 {
		return fmt.Errorf("uds: enabled without any [[uds.peer]]")
	}
	seen := map[int]bool{}
	seenSID := map[string]bool{}
	for i, p := range u.Peers {
		if runtime.GOOS == "windows" {
			// FR-21.9: named-pipe peers are identified by user SID.
			if p.SID == "" {
				return fmt.Errorf("uds.peer[%d]: on Windows a peer is identified by sid (the user SID), not uid", i)
			}
			if seenSID[strings.ToUpper(p.SID)] {
				return fmt.Errorf("uds.peer[%d]: sid %s registered twice", i, p.SID)
			}
			seenSID[strings.ToUpper(p.SID)] = true
		} else if p.SID != "" {
			return fmt.Errorf("uds.peer[%d]: sid identifies Windows named-pipe peers; on %s set uid", i, runtime.GOOS)
		} else if seen[p.UID] {
			return fmt.Errorf("uds.peer[%d]: uid %d registered twice", i, p.UID)
		}
		seen[p.UID] = true
		if c.FindPrincipal(p.Principal) == nil {
			return fmt.Errorf("uds.peer[%d]: unknown principal %q", i, p.Principal)
		}
		if !strings.HasPrefix(p.KeyHash, "$argon2id$") {
			return fmt.Errorf("uds.peer[%d]: key_hash is not an Argon2id hash", i)
		}
	}
	return nil
}
