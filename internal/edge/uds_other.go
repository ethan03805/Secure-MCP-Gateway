//go:build !windows

package edge

import (
	"errors"
	"fmt"
	"net"
)

// udsSupported reports whether the UDS Harness Profile can listen here.
func udsSupported() error { return nil }

// listenPlatform has no platform listener off Windows.
func (g *Gateway) listenPlatform() (net.Listener, bool, error) { return nil, false, nil }

// identifyPeer reads the peer UID of a Unix-domain socket connection.
func (g *Gateway) identifyPeer(c net.Conn) (udsPeerID, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return udsPeerID{}, errors.New("uds: not a Unix-domain socket connection")
	}
	uid, err := peerUID(uc)
	peer, registered := g.cfg.UDS.Peer(uid)
	return udsPeerID{field: "peer_uid", value: uid, client: fmt.Sprintf("uds:%d", uid), peer: peer, registered: registered}, err
}
