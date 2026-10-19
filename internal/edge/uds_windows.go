//go:build windows

package edge

import "errors"

// udsSupported refuses the UDS Harness Profile on Windows: its transport
// there is the CP-02 named pipe (FR-21.8, SR-2.8-5) with the SID peer
// mapping of FR-21.9, which is not implemented, and an AF_UNIX socket
// would have neither peer credentials nor a group-owned mode.
func udsSupported() error {
	return errors.New("uds: the UDS Harness Profile is not available on Windows yet (the FR-21.8 named-pipe transport is not implemented); disable [uds] and use the TLS listener")
}
