package egress

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// Hosted egress for the bundled ContextForge instance (E-36, SRS FR-22.40,
// FR-22.9, SR-3.5-2, planned for v1.3.0).
//
// The bundled instance reaches every hosted server only through the
// Egress Broker. A Hosted set is one listener, opened before the instance
// starts, so that its address can be the only destination of the
// instance's network namespace in the Enforced profile and the only entry
// of its SSRF allowlist. Each hosted package (and each hosted-entry probe)
// gets its own endpoint on that listener: a URL prefix with a random key,
// bound to one host and port, for which the broker originates TLS. The
// key is what binds a request to an endpoint: a request whose first path
// segment is not a live key is refused, so another local process that
// finds the listener cannot use an endpoint it was not given. Requests
// are checked as endpoint operations are (grant, DNS, address classes,
// redirects within the endpoint's host, limits, secret fingerprints) and
// recorded with the endpoint's server name. S1 header grants (BindHeader)
// apply to them by that name.
//
// Capabilities (SR-5.16-1) are not required on these endpoints: the
// bundled instance makes the upstream request for a call the Gateway has
// already decided, and ContextForge does not pass a per-call header on.

// HostedEndpoint is one live endpoint.
type HostedEndpoint struct {
	// Server is the name the endpoint's operations and S1 grants use: the
	// hosted package's alias, or the probe's name.
	Server string
	Host   string
	Port   int
	// Base is the URL the bundled instance uses for the endpoint; append
	// the hosted URL's path and query to it.
	Base string
	key  string
	in   *instance
}

// URL is the endpoint URL of a hosted URL (its path and query on Base).
func (e HostedEndpoint) URL(hosted string) (string, error) {
	u, err := url.Parse(hosted)
	if err != nil {
		return "", err
	}
	out := e.Base + u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, nil
}

// Hosted is the listener of the hosted endpoints and the broker that
// serves them.
type Hosted struct {
	b     *Broker
	srv   *http.Server
	base  string
	allow netip.AddrPort

	mu    sync.Mutex
	byKey map[string]*HostedEndpoint
}

// HostedOptions returns the broker options of a hosted set from the
// [egress] table: its limits, DNS servers and destination trust, whether
// or not [egress] is enabled. Evidence and Log are the caller's.
func HostedOptions(cfg *config.Config, rec audit.Recorder, log *slog.Logger) (Options, error) {
	e := cfg.Egress
	res, roots, err := destinationTrust(e)
	if err != nil {
		return Options{}, err
	}
	return Options{Evidence: rec, Log: log, Recent: e.RecentRecords, Resolver: res, RootCAs: roots,
		Limits: Limits{RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes, OperationTimeout: e.OperationTimeout.Duration,
			DialTimeout: e.DialTimeout.Duration, RequestsPerMinute: e.RequestsPerMinute, BytesPerMinute: e.BytesPerMinute}}, nil
}

// NewHosted opens the hosted listener on listen (port 0: any free port).
// guest, when valid, is the address the bundled instance uses for listen
// (the slirp4netns host-loopback address); otherwise it uses listen. The
// grants, capabilities and proxy settings of o are replaced: the set's
// endpoints are its only grants.
func NewHosted(o Options, listen netip.AddrPort) (*Hosted, error) {
	return NewHostedGuest(o, listen, netip.Addr{})
}

// NewHostedGuest is NewHosted with the guest address of the listener.
func NewHostedGuest(o Options, listen netip.AddrPort, guest netip.Addr) (*Hosted, error) {
	h := &Hosted{byKey: map[string]*HostedEndpoint{}}
	o.Grants = hostedGrants{h}
	o.RequireCapability = false
	o.ProxyEnv = false
	b, err := New(o)
	if err != nil {
		return nil, err
	}
	h.b = b
	ln, err := net.Listen("tcp", listen.String())
	if err != nil {
		return nil, fmt.Errorf("egress: hosted listener on %s: %w", listen, err)
	}
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, err
	}
	if guest.IsValid() {
		ap = netip.AddrPortFrom(guest, ap.Port())
	}
	h.allow = ap
	h.base = "http://" + ap.String()
	h.srv = &http.Server{Handler: http.HandlerFunc(h.serve), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute,
		ErrorLog: slog.NewLogLogger(b.o.Log.Handler(), slog.LevelDebug)}
	go func() { _ = h.srv.Serve(ln) }()
	return h, nil
}

// Broker is the broker of the set (S1 header grants, records).
func (h *Hosted) Broker() *Broker { return h.b }

// Allow is the address and port the bundled instance must be able to
// reach: the only destination of its namespace (FR-22.24, SR-4.5-4).
func (h *Hosted) Allow() netip.AddrPort { return h.allow }

// Add opens an endpoint for server bound to host and port (443 when 0).
func (h *Hosted) Add(server, host string, port int) (HostedEndpoint, error) {
	if server == "" {
		return HostedEndpoint{}, errors.New("egress: a hosted endpoint needs a server name")
	}
	ch, err := canonicalHost(host, false)
	if err != nil {
		return HostedEndpoint{}, err
	}
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return HostedEndpoint{}, errors.New("egress: invalid port")
	}
	var k [16]byte
	if _, err := rand.Read(k[:]); err != nil {
		return HostedEndpoint{}, err
	}
	key := hex.EncodeToString(k[:])
	in := &instance{id: ids.New(), alias: server, attached: h.b.o.Now(), endpoints: map[string]string{}}
	e := &HostedEndpoint{Server: server, Host: ch, Port: port, Base: h.base + "/" + key, key: key, in: in}
	// The key is a secret of the bundled instance; the evidence names the
	// endpoint by its server and destination only.
	if err := h.b.o.Evidence.Record(audit.Event{Class: "egress", Origin: Origin, Outcome: "attached", PolicyStatus: "not_evaluated",
		Detail: map[string]any{"instance": in.id, "server": server, "enforced": false, "hosted": true, "destination": joinHostPort(ch, port), "listener": h.allow.String()}}); err != nil {
		return HostedEndpoint{}, fmt.Errorf("egress: evidence: %w", err)
	}
	h.b.mu.Lock()
	if h.b.closed {
		h.b.mu.Unlock()
		return HostedEndpoint{}, errors.New("egress: broker is closed")
	}
	h.b.instances[in.id] = in
	h.b.mu.Unlock()
	h.mu.Lock()
	h.byKey[key] = e
	h.mu.Unlock()
	return *e, nil
}

// Remove closes an endpoint; later requests to it are refused.
func (h *Hosted) Remove(e HostedEndpoint) {
	h.mu.Lock()
	cur := h.byKey[e.key]
	delete(h.byKey, e.key)
	h.mu.Unlock()
	if cur != nil {
		_ = h.b.detach(cur.in)
	}
}

// Endpoints returns the live endpoints (without their keys' URLs).
func (h *Hosted) Endpoints() []HostedEndpoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HostedEndpoint, 0, len(h.byKey))
	for _, e := range h.byKey {
		c := *e
		c.Base, c.key, c.in = "", "", nil
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b HostedEndpoint) int { return strings.Compare(a.Server, b.Server) })
	return out
}

// Close closes the listener and every endpoint.
func (h *Hosted) Close() error {
	err := h.srv.Close()
	h.mu.Lock()
	h.byKey = map[string]*HostedEndpoint{}
	h.mu.Unlock()
	return errors.Join(err, h.b.Close())
}

type hostedGrants struct{ h *Hosted }

// Grants implements GrantSource: the endpoint of server, if live.
func (g hostedGrants) Grants(server string) []Grant {
	g.h.mu.Lock()
	defer g.h.mu.Unlock()
	var out []Grant
	for _, e := range g.h.byKey {
		if e.Server == server {
			out = append(out, Grant{Server: server, Host: e.Host, Ports: []int{e.Port}, Methods: []string{http.MethodGet, http.MethodPost, http.MethodDelete},
				Class: ClassAPI})
		}
	}
	return out
}

// unknownEndpoint records refusals of requests that name no live key.
var unknownEndpoint = &instance{id: "hosted-unknown", alias: "contextforge-hosted"}

func (h *Hosted) serve(w http.ResponseWriter, r *http.Request) {
	seg, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	h.mu.Lock()
	e := h.byKey[seg]
	h.mu.Unlock()
	if e == nil {
		rec := h.b.newRecord(unknownEndpoint, ModeEndpoint, r.Method)
		h.b.refuse(w, rec, ReasonNoGrant, "no hosted endpoint at this path")
		return
	}
	rec := h.b.newRecord(e.in, ModeEndpoint, r.Method)
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		h.b.refuse(w, rec, ReasonBadRequest, "send origin-form requests to a hosted endpoint")
		return
	}
	rawRest := ""
	if r.URL.RawPath != "" {
		_, rawRest, _ = strings.Cut(strings.TrimPrefix(r.URL.RawPath, "/"), "/")
		rawRest = "/" + rawRest
	}
	target := &url.URL{Scheme: "https", Host: urlHost(e.Host, e.Port, 443), Path: "/" + rest, RawPath: rawRest, RawQuery: r.URL.RawQuery}
	h.b.forwardWith(w, r, rec, target, true, func(body io.Reader, dst io.Writer, flush func()) error {
		return rewriteEndpointEvents(body, dst, flush, e.Host, e.Port, "/"+e.key)
	})
}

// rewriteEndpointEvents copies a Server-Sent Events stream, flushing after
// each event, and rewrites the data of "endpoint" events (the legacy SSE
// transport's message URL) so that the instance posts its messages through
// the same endpoint: a path, or a URL on the endpoint's own host, becomes
// that path under prefix. A URL on another host is replaced by a path
// that no endpoint serves, so the message cannot leave through it.
func rewriteEndpointEvents(body io.Reader, dst io.Writer, flush func(), host string, port int, prefix string) error {
	br := bufio.NewReaderSize(body, 32<<10)
	event := ""
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimRight(line, "\r\n")
			switch {
			case trimmed == "":
				event = ""
			case strings.HasPrefix(trimmed, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			case event == "endpoint" && strings.HasPrefix(trimmed, "data:"):
				v := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				line = "data: " + endpointPath(v, host, port, prefix) + line[len(trimmed):]
			}
			if _, werr := io.WriteString(dst, line); werr != nil {
				return werr
			}
			if trimmed == "" {
				flush()
			}
		}
		if err != nil {
			flush()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func endpointPath(v, host string, port int, prefix string) string {
	u, err := url.Parse(v)
	if err != nil {
		return prefix + "/invalid-endpoint"
	}
	if u.IsAbs() || u.Host != "" {
		p, _ := portOf(u.Port(), defaultPort(u.Scheme))
		h, herr := canonicalHost(u.Hostname(), false)
		if herr != nil || h != host || p != port || u.Scheme != "https" {
			return prefix + "/foreign-endpoint"
		}
	}
	out := u.EscapedPath()
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return prefix + out
}
