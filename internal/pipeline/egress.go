package pipeline

import (
	"context"
	"net/netip"
)

// EgressAttacher connects one server instance to the Egress Broker (E-18).
// A Launcher calls Attach before the instance's code runs and closes the
// returned attachment after the instance has exited. The attachment's
// environment is added to the instance environment (FR-5.37).
//
// The broker (internal/egress) implements this interface. A confining
// launcher (E-16) that implements EgressAware receives the attacher through
// SetEgress and passes the sandbox network in EgressRequest.Network; any
// other launcher is wrapped so that Attach runs with a nil network, which
// gives the instance proxy variables without enforcement (standalone
// profile).
type EgressAttacher interface {
	Attach(ctx context.Context, req EgressRequest) (*EgressAttachment, error)
}

// EgressAware is implemented by launchers that attach egress themselves,
// because the sandbox network must exist before the broker can bind to it
// and confine it.
type EgressAware interface {
	SetEgress(EgressAttacher)
}

// EgressRequest describes the instance being attached.
type EgressRequest struct {
	// Alias is the server alias; grants are looked up by it.
	Alias string
	// Network is the instance's sandbox network. Nil means the instance
	// shares the host network (standalone profile): the broker listens on
	// loopback and nothing is enforced.
	Network *EgressNetwork
}

// EgressNetwork is the sandbox network of one instance (E-16).
type EgressNetwork struct {
	// NetNS is the path of the instance's network namespace, for example
	// /proc/<pid>/ns/net or /run/netns/<name>. The broker installs nftables
	// rules in it so that the only reachable endpoints are the broker's
	// listeners (SR-4.5-1).
	NetNS string
	// ListenAddr is the host address, reachable from inside the namespace,
	// on which the broker binds the instance's listeners.
	ListenAddr netip.Addr
}

// EgressAttachment is the result of Attach.
type EgressAttachment struct {
	// ID identifies the attachment in evidence and in the control API.
	ID string
	// Env holds the variables to add to the instance environment: proxy
	// variables and one base URL per granted destination endpoint.
	Env map[string]string
	// Enforced reports whether network rules confine the instance to the
	// broker. False in the standalone profile, where the variables are
	// advisory.
	Enforced bool
	// Close stops the instance's listeners and removes its rules. It is
	// safe to call more than once.
	Close func() error
}

// NoEgress attaches nothing: the instance gets no egress variables. It is
// the default when no broker is configured.
type NoEgress struct{}

// Attach implements EgressAttacher.
func (NoEgress) Attach(context.Context, EgressRequest) (*EgressAttachment, error) {
	return &EgressAttachment{Env: map[string]string{}, Close: func() error { return nil }}, nil
}
