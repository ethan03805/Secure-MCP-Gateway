package winsandbox

// PathGrant is one filesystem grant of a revision's AppContainer SID
// (SR-4.6-2).
type PathGrant struct {
	Path  string `json:"path"`
	Write bool   `json:"write"`
}

// Placement is what the elevated enable step sets up for one enabled server
// revision in the machine mode (FR-21.13, FR-21.14, SR-4.6-2): its
// AppContainer profile, the access entries on the package tree (read and
// execute), the scratch directory (modify) and the granted filesystem
// roots, the WFP filters and the loopback exemption, and the Egress
// Broker's loopback port for the revision's instance.
type Placement struct {
	ServerID string `json:"server_id"`
	Revision string `json:"revision"`
	// Profile is the AppContainer profile name (ProfileName).
	Profile string `json:"profile"`
	// SID is the AppContainer SID in string form.
	SID string `json:"sid"`
	// Tree is the revision's unpacked package tree.
	Tree string `json:"tree"`
	// Scratch is the instance's scratch directory.
	Scratch string `json:"scratch"`
	// Roots are the granted filesystem roots: the intersection of the
	// manifest's slots and the configured slot paths.
	Roots []PathGrant `json:"roots"`
	// BrokerPort is the loopback port on which the Egress Broker serves the
	// revision's instance as an HTTP proxy, and the only port the WFP
	// filters let the AppContainer reach.
	BrokerPort uint16 `json:"broker_port"`
}

// PlacementRequest asks for the placement of one revision.
type PlacementRequest struct {
	ServerID, Revision string
	Tree, Scratch      string
	Roots              []PathGrant
}
