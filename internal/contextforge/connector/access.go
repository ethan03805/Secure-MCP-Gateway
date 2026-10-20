package connector

import "github.com/ethan03805/secure-mcp-gateway/internal/library"

// ProposalView is an import proposal as the control API shows it.
type ProposalView = proposal

// PublicKey is the minisign public key of the catalog import key, as an
// Administrator enrolls it (smcpctl trust add).
func (c *Connector) PublicKey() []byte { return append([]byte(nil), c.pub...) }

// SetSuspend sets the function that suspends an enabled revision for
// cause (smcpd passes library.Runtime.SuspendRevision).
func (c *Connector) SetSuspend(f func(id, rev string, cause error) error) { c.o.Suspend = f }

// Revisions lists the library's revisions (tests and the hostile suite).
func (c *Connector) Revisions() []library.Revision { return c.o.Library.Revisions() }
