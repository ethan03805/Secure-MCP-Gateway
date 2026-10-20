package secrets

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// ProbeHeader is the S1 binding of a probe secret: the operator secret
// Name is inserted as Header (built from Template, "{secret}" by default)
// on the requests of the probe Server to Destination.
type ProbeHeader struct {
	Name        string
	Server      string
	Destination string
	Header      string
	Template    string
}

// BindServerHeaders makes the S1 deliveries of server's Secret Use Policy
// bindings through the broker's injector before the server is launched,
// with the usual decisions and evidence. The ContextForge Connector needs
// them while it registers a hosted package's gateway, because ContextForge
// connects to the hosted server at registration (FR-22.15). The other
// modes are not delivered. The returned function withdraws them.
func (b *Broker) BindServerHeaders(ctx context.Context, server string) (func(), error) {
	b.mu.Lock()
	use, stopped := b.use, b.stopped
	b.mu.Unlock()
	if use == nil {
		return func() {}, nil
	}
	inst := &instance{alias: server, correlated: ids.New(), s2: map[string]string{}}
	for _, bd := range use.byServer[server] {
		if bd.Mode != ModeS1 {
			continue
		}
		d, _, _, err := b.deliverLaunch(ctx, inst, bd, use.Revision, stopped)
		if err != nil {
			b.teardown(inst, "registration_denied")
			return nil, err
		}
		inst.delivered = append(inst.delivered, d)
	}
	return func() { b.teardown(inst, "registration_done") }, nil
}

// BindProbeHeader delivers an operator secret for one hosted-entry probe
// of the ContextForge Connector (SRS FR-22.9, FR-22.15) in mode S1 only:
// the value goes to inj, the Egress Broker of the probe's endpoint, which
// inserts the header on the probe's requests to the entry's host. It
// never reaches the bundled instance. The value's fingerprint is
// registered, and one secret_use event names the probe, the destination
// and the secret's reference (never the value). The returned function
// withdraws the binding and records that.
func (b *Broker) BindProbeHeader(ctx context.Context, inj pipeline.SecretHeaderInjector, p ProbeHeader) (func(), error) {
	if inj == nil {
		return nil, errors.New("secrets: no egress endpoint for the probe secret")
	}
	if p.Server == "" || p.Destination == "" || p.Header == "" {
		return nil, errors.New("secrets: a probe secret needs a probe, a destination and a header")
	}
	tmpl := p.Template
	if tmpl == "" {
		tmpl = "{secret}"
	}
	b.mu.Lock()
	rec := b.rec
	b.mu.Unlock()
	if rec == nil {
		return nil, ErrNoEvidence
	}
	op, err := b.vault.open(p.Name, 0) // refuses component credentials
	if err != nil {
		return nil, fmt.Errorf("probe secret %s: %w", p.Name, err)
	}
	defer wipe(op.Value)
	b.mu.Lock()
	_, suspended := b.suspended[op.Ref]
	b.mu.Unlock()
	if suspended {
		return nil, fmt.Errorf("probe secret %s is suspended", p.Name)
	}
	b.fp.Register(op.Ref, op.Version, op.Value)
	grant := ids.New()
	refv := fmt.Sprintf("%s@%d", op.Ref, op.Version)
	detail := map[string]any{"purpose": "contextforge_probe", "server": p.Server, "destination": p.Destination, "header": p.Header,
		"secret_ref": refv, "mode": ModeS1, "grant": grant}
	if err := inj.BindHeader(ctx, pipeline.HeaderGrant{GrantID: grant, Server: p.Server, Slot: "probe", Destination: p.Destination,
		Header: p.Header, Template: tmpl, SecretRef: op.Ref, Version: op.Version, Value: slices.Clone(op.Value)}); err != nil {
		return nil, err
	}
	if err := rec.Commit(audit.Event{Class: "secret_use", Origin: "E-20", Outcome: "delivered", PolicyStatus: "not_evaluated", Detail: detail}); err != nil {
		inj.Withdraw(grant)
		return nil, fmt.Errorf("evidence unavailable: %w", err)
	}
	return func() {
		inj.Withdraw(grant)
		_ = rec.Record(audit.Event{Class: "secret_use", Origin: "E-20", Outcome: "withdrawn", PolicyStatus: "not_evaluated",
			Detail: map[string]any{"purpose": "contextforge_probe", "server": p.Server, "secret_ref": refv, "grant": grant}})
	}, nil
}
