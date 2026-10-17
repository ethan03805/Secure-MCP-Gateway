package pipeline

import "context"

// EgressAttachment is what the Egress Broker (E-18) gives one sandboxed
// server instance at launch (I-25, FR-5.37).
//
// Network is the container network the instance joins. "none" (the
// default) leaves the instance with a loopback interface only, so it has no
// route anywhere (SR-4.5-1). A broker that grants egress returns the name of
// a network whose only reachable endpoints are its own (it owns that
// network and the nftables rules around it).
//
// Env holds the base URLs of the instance's egress endpoints under the
// variable names the manifest declares; the launcher adds them to the
// instance environment. Values must not contain secrets.
//
// Release is called once when the instance is torn down; it may be nil.
type EgressAttachment struct {
	Network string
	Env     map[string]string
	Release func()
}

// NetworkNone is the EgressAttachment network of an instance without egress.
const NetworkNone = "none"

// EgressAttacher is the seam between the Server Runtime Manager (E-15) and
// the Egress Broker (E-18). The confining launcher calls Attach before it
// creates each instance; instanceID is unique per instance and is also the
// container label `smcp.instance`. An error refuses the launch.
type EgressAttacher interface {
	Attach(ctx context.Context, spec ServerSpec, instanceID string) (EgressAttachment, error)
}

// NoEgress is the default EgressAttacher: every instance gets network
// "none" and no endpoint variables.
type NoEgress struct{}

// Attach implements EgressAttacher.
func (NoEgress) Attach(context.Context, ServerSpec, string) (EgressAttachment, error) {
	return EgressAttachment{Network: NetworkNone}, nil
}
