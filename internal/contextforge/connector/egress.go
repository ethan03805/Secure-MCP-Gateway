package connector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

// Hosted egress (SRS FR-22.40, FR-22.9, FR-22.15, SR-3.5-2).
//
// Before the bundled instance starts, the Connector opens the hosted
// egress listener of an Egress Broker (egress.Hosted) where the instance
// can reach it, and makes that address the instance's only SSRF allowlist
// entry and, in the Enforced profile, the only destination of its network
// namespace. Each enabled hosted package is registered with the URL of
// its own endpoint on that listener, bound to its manifest's host and
// port; each hosted-entry probe gets an endpoint of its own for the
// entry's host, removed when the probe ends. A probe secret is inserted
// by the broker on the probe's requests to the entry's host (S1); the
// bundled instance never holds it.

// ReasonProbeSecretRequired: a hosted entry needs an API key and the
// import names no probe secret (FR-22.9).
const ReasonProbeSecretRequired = "PROBE_SECRET_REQUIRED"

// ReasonHostedSecretMode: a secret of a hosted package was to be delivered
// in a mode other than S1 at its endpoint (FR-22.15).
const ReasonHostedSecretMode = "HOSTED_SECRET_MODE"

// ProbeSecret names the vault secret a hosted-entry probe sends and how
// (FR-22.9). The broker inserts Header, built from Template, on the
// probe's requests to the entry's host.
type ProbeSecret struct {
	Secret   string `json:"secret"`
	Header   string `json:"header,omitempty"`   // default Authorization
	Template string `json:"template,omitempty"` // default "Bearer {secret}"
}

// lateRecorder holds the hosted broker's evidence until the Gateway's
// journal is attached (SetRecorder): packages resolve during app.Start,
// before the Connector has the recorder.
type lateRecorder struct {
	mu  sync.Mutex
	rec audit.Recorder
	buf []audit.Event
}

const lateMax = 10000

func (l *lateRecorder) write(ev audit.Event, commit bool) error {
	l.mu.Lock()
	rec := l.rec
	if rec == nil {
		defer l.mu.Unlock()
		if len(l.buf) >= lateMax {
			return errors.New("contextforge connector: the evidence journal is not attached yet")
		}
		l.buf = append(l.buf, ev)
		return nil
	}
	l.mu.Unlock()
	if commit {
		return rec.Commit(ev)
	}
	return rec.Record(ev)
}

func (l *lateRecorder) Record(ev audit.Event) error { return l.write(ev, false) }
func (l *lateRecorder) Commit(ev audit.Event) error { return l.write(ev, true) }

func (l *lateRecorder) attach(rec audit.Recorder) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rec = rec
	for _, ev := range l.buf {
		_ = rec.Record(ev)
	}
	l.buf = nil
}

// prepareEgress opens the hosted egress listener once and gives the
// instance its address (FR-22.27, FR-22.24).
func (c *Connector) prepareEgress(ctx context.Context) error {
	c.egMu.Lock()
	defer c.egMu.Unlock()
	if c.o.EndpointFor != nil {
		c.inst.SetSSRFAllowed(c.o.SSRFAllowed)
		return nil
	}
	if c.eg == nil {
		acc, err := c.inst.HostAccess(ctx)
		if err != nil {
			return err
		}
		if c.late == nil {
			c.late = &lateRecorder{}
			if c.o.Recorder != nil {
				c.late.attach(c.o.Recorder)
			}
		}
		opts, err := egress.HostedOptions(c.o.Config, c.late, c.o.Log)
		if err != nil {
			return err
		}
		open := c.o.Egress
		if open == nil {
			open = func(o egress.Options, listen netip.AddrPort, guest netip.Addr) (*egress.Hosted, error) {
				return egress.NewHostedGuest(o, listen, guest)
			}
		}
		h, err := open(opts, netip.AddrPortFrom(acc.Listen, 0), acc.Guest)
		if err != nil {
			return err
		}
		c.eg = h
		c.inst.SetSSRFAllowed(append(acc.SSRFAllowed(), c.o.SSRFAllowed...))
	}
	c.inst.SetEgressAllow(c.eg.Allow())
	return nil
}

func (c *Connector) closeEgress() {
	c.egMu.Lock()
	defer c.egMu.Unlock()
	if c.eg != nil {
		_ = c.eg.Close()
		c.eg = nil
	}
}

// HostedEgress returns the hosted egress listener (nil before the first
// start): smcpd routes the hosted packages' S1 secrets to its broker.
func (c *Connector) HostedEgress() *egress.Hosted {
	c.egMu.Lock()
	defer c.egMu.Unlock()
	return c.eg
}

// hostPort is the host and port of a hosted URL (443 by default).
func hostPort(raw string) (string, int, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", 0, fmt.Errorf("hosted URL %q has no host", raw)
	}
	port := 443
	if s := u.Port(); s != "" {
		if port, err = strconv.Atoi(s); err != nil {
			return "", 0, fmt.Errorf("hosted URL %q: %w", raw, err)
		}
	}
	return strings.ToLower(u.Hostname()), port, nil
}

// probeEndpoint returns the URL the probe of a hosted entry registers: an
// endpoint of its own for the entry's host, with the probe secret bound
// at it when one is named. release removes both.
func (c *Connector) probeEndpoint(ctx context.Context, proposalID, hostedURL string, ps *ProbeSecret) (string, func(), error) {
	if c.o.EndpointFor != nil {
		u, err := c.o.EndpointFor(hostedURL)
		return u, func() {}, err
	}
	h := c.HostedEgress()
	if h == nil {
		return "", func() {}, errors.New("the hosted egress listener is not open")
	}
	host, port, err := hostPort(hostedURL)
	if err != nil {
		return "", func() {}, err
	}
	ep, err := h.Add("contextforge-probe-"+proposalID, host, port)
	if err != nil {
		return "", func() {}, err
	}
	withdraw := func() {}
	release := func() {
		withdraw()
		h.Remove(ep)
	}
	if ps != nil && ps.Secret != "" {
		header, tmpl := ps.Header, ps.Template
		if header == "" {
			header = "Authorization"
			if tmpl == "" {
				tmpl = "Bearer {secret}"
			}
		}
		w, err := c.o.Broker.BindProbeHeader(ctx, h.Broker(), secrets.ProbeHeader{Name: ps.Secret, Server: ep.Server,
			Destination: net.JoinHostPort(host, strconv.Itoa(port)), Header: header, Template: tmpl})
		if err != nil {
			release()
			return "", func() {}, packaging.Wrap(ReasonProbeSecretRequired, "binding the probe secret", err)
		}
		withdraw = w
	}
	u, err := ep.URL(hostedURL)
	if err != nil {
		release()
		return "", func() {}, err
	}
	return u, release, nil
}

// packageEgress is a registered hosted package's endpoint, its alias and
// destination, and the withdrawal of its registration-time S1 grants.
type packageEgress struct {
	ep       egress.HostedEndpoint
	alias    string
	dest     destination
	withdraw func()
}

// packageEndpoint returns the URL a hosted package's gateway is
// registered with: its own endpoint, named after the package's alias so
// that the Secret Broker's S1 grants for the alias apply at it. An
// earlier endpoint of the same revision is removed.
func (c *Connector) packageEndpoint(alias, revKey, hostedURL string) (string, error) {
	if c.o.EndpointFor != nil {
		return c.o.EndpointFor(hostedURL)
	}
	h := c.HostedEgress()
	if h == nil {
		return "", errors.New("the hosted egress listener is not open")
	}
	host, port, err := hostPort(hostedURL)
	if err != nil {
		return "", err
	}
	c.dropEndpoint(revKey)
	ep, err := h.Add(alias, host, port)
	if err != nil {
		return "", err
	}
	c.egMu.Lock()
	c.endpoints[revKey] = &packageEgress{ep: ep, alias: alias, dest: destination{host, port}}
	c.egMu.Unlock()
	return ep.URL(hostedURL)
}

// bindRegistrationSecrets makes the S1 deliveries of a hosted package's
// alias before its gateway is registered, since ContextForge connects to
// the hosted server at registration; they stay bound while the package is
// registered (FR-22.15).
func (c *Connector) bindRegistrationSecrets(ctx context.Context, alias, revKey string) error {
	if c.o.Broker == nil || c.o.EndpointFor != nil {
		return nil
	}
	w, err := c.o.Broker.BindServerHeaders(ctx, alias)
	if err != nil {
		return err
	}
	c.egMu.Lock()
	pe := c.endpoints[revKey]
	if pe != nil {
		pe.withdraw = w
	}
	c.egMu.Unlock()
	if pe == nil {
		w()
	}
	return nil
}

// dropEndpoint removes a package's endpoint and withdraws its
// registration-time grants (suspension, drift, a new registration).
func (c *Connector) dropEndpoint(revKey string) {
	c.egMu.Lock()
	pe, ok := c.endpoints[revKey]
	delete(c.endpoints, revKey)
	h := c.eg
	c.egMu.Unlock()
	if !ok {
		return
	}
	if pe.withdraw != nil {
		pe.withdraw()
	}
	if h != nil {
		h.Remove(pe.ep)
	}
}

// S1Router is the Secret Broker's secret-header injector while the
// bundled instance is configured: an S1 grant of a hosted package's alias
// is bound at the hosted egress broker, and only for the package's own
// host and port (FR-22.15); every other grant goes to the Gateway's
// Egress Broker (nil without [egress]).
type S1Router struct {
	c    *Connector
	next pipeline.SecretHeaderInjector

	mu     sync.Mutex
	hosted map[string]bool // grant IDs bound at the hosted broker
}

// S1Router returns the router over next.
func (c *Connector) S1Router(next pipeline.SecretHeaderInjector) *S1Router {
	return &S1Router{c: c, next: next, hosted: map[string]bool{}}
}

// BindHeader implements pipeline.SecretHeaderInjector.
func (r *S1Router) BindHeader(ctx context.Context, g pipeline.HeaderGrant) error {
	if dest, ok := r.c.hostedDestination(g.Server); ok {
		host, port, err := splitDestination(g.Destination)
		if err != nil || host != dest.host || (port != 0 && port != dest.port) {
			return packaging.Errf(ReasonHostedSecretMode, "%s is a hosted package: its secrets are inserted only at its endpoint for %s:%d, not %q",
				g.Server, dest.host, dest.port, g.Destination)
		}
		h := r.c.HostedEgress()
		if h == nil {
			return errors.New("the hosted egress listener is not open")
		}
		if err := h.Broker().BindHeader(ctx, g); err != nil {
			return err
		}
		r.mu.Lock()
		r.hosted[g.GrantID] = true
		r.mu.Unlock()
		return nil
	}
	if r.next == nil {
		return errors.New("no Egress Broker inserts headers ([egress] enabled is false)")
	}
	return r.next.BindHeader(ctx, g)
}

// Withdraw implements pipeline.SecretHeaderInjector.
func (r *S1Router) Withdraw(grantID string) {
	r.mu.Lock()
	hosted := r.hosted[grantID]
	delete(r.hosted, grantID)
	r.mu.Unlock()
	if hosted {
		if h := r.c.HostedEgress(); h != nil {
			h.Broker().Withdraw(grantID)
		}
		return
	}
	if r.next != nil {
		r.next.Withdraw(grantID)
	}
}

type destination struct {
	host string
	port int
}

func splitDestination(d string) (string, int, error) {
	if h, p, err := net.SplitHostPort(d); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, err
		}
		return strings.ToLower(strings.TrimSuffix(h, ".")), n, nil
	}
	return strings.ToLower(strings.TrimSuffix(d, ".")), 0, nil
}

// hostedDestination returns the host and port of a hosted package with
// an endpoint, by its alias.
func (c *Connector) hostedDestination(alias string) (destination, bool) {
	c.egMu.Lock()
	defer c.egMu.Unlock()
	for _, pe := range c.endpoints {
		if pe.alias == alias {
			return pe.dest, true
		}
	}
	return destination{}, false
}
