//go:build windows

package edge

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/winpipe"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// udsSupported is not reached on Windows: listenPlatform serves the
// profile over the named pipe and never opens an AF_UNIX socket (FR-21.8).
func udsSupported() error {
	return errors.New("uds: Unix-domain sockets are not used on Windows")
}

// listenPlatform creates the CP-02 named pipe for the UDS Harness Profile
// (FR-21.8) with the SR-2.8-6 security descriptor: read and write for the
// account running smcpd and for the harness clients (the local group named
// by [uds] group when it exists, and in the per-user mode the installing
// user, who is the same account), deny NETWORK and ANONYMOUS LOGON,
// FILE_FLAG_FIRST_PIPE_INSTANCE and PIPE_REJECT_REMOTE_CLIENTS. A pipe
// that already exists is refused with pipe_squatted.
func (g *Gateway) listenPlatform() (net.Listener, bool, error) {
	u := g.cfg.UDS
	if !strings.HasPrefix(strings.ToLower(u.Path), `\\.\pipe\`) {
		return nil, true, fmt.Errorf(`uds: on Windows [uds] path must be a named pipe (\\.\pipe\...), not %q`, u.Path)
	}
	self, err := winsec.ProcessUserSID()
	if err != nil {
		return nil, true, err
	}
	var clients []string
	if u.Group != "" {
		if sid, err := winsec.LookupSID(u.Group); err == nil {
			clients = append(clients, sid)
		}
	}
	ln, err := winpipe.Listen(u.Path, winpipe.Entries(self, clients...))
	if err != nil {
		return nil, true, err
	}
	return ln, true, nil
}

// identifyPeer reads the user SID of the pipe client's token (FR-21.9).
func (g *Gateway) identifyPeer(c net.Conn) (udsPeerID, error) {
	pc, ok := c.(*winpipe.Conn)
	if !ok {
		return udsPeerID{}, errors.New("uds: not a named-pipe connection")
	}
	sid, err := pc.ClientSID()
	if err != nil {
		return udsPeerID{field: "peer_sid", value: "", client: "uds:unknown"}, err
	}
	peer, registered := g.cfg.UDS.PeerSID(sid)
	return udsPeerID{field: "peer_sid", value: sid, client: "uds:" + sid, peer: peer, registered: registered}, nil
}
