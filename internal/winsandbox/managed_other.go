//go:build !windows

package winsandbox

import "time"

// Managed is a running managed process; off Windows StartManaged returns
// ErrUnsupported.
type Managed struct{}

// StartManaged returns ErrUnsupported off Windows.
func StartManaged(ManagedSpec) (*Managed, error) { return nil, ErrUnsupported }

// PID returns 0.
func (*Managed) PID() int { return 0 }

// Done returns a closed channel.
func (*Managed) Done() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// Wait returns ErrUnsupported.
func (*Managed) Wait() error { return ErrUnsupported }

// Stop returns ErrUnsupported.
func (*Managed) Stop(time.Duration) error { return ErrUnsupported }
