package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Experimental upstream relay (ContextForge spike, docs/contextforge-spike.md).
//
// The Gateway's southbound transport is stdio only (Streamable HTTP
// southbound, FR-5.28 to FR-5.31, is deferred). Until it exists, a server
// that speaks only Streamable HTTP, such as a ContextForge virtual server,
// can be configured as a command-launched backend that runs
//
//	smcp-stdio --experimental-upstream http://127.0.0.1:4444/servers/<id>/mcp
//
// with the bearer token delivered by the Secret Broker in UpstreamTokenEnv
// (S4) or as a file named by UpstreamTokenFileEnv (S2, S3). The relay is the
// same one smcp-stdio uses towards the Gateway; only the token source and
// the URL rules differ. It is not part of any requirement and may change.

// UpstreamTokenEnv carries the upstream bearer token.
const UpstreamTokenEnv = "SMCP_UPSTREAM_TOKEN"

// UpstreamTokenFileEnv names a file holding the upstream bearer token.
const UpstreamTokenFileEnv = "SMCP_UPSTREAM_TOKEN_FILE"

// maxUpstreamTokenBytes bounds a token read from a file.
const maxUpstreamTokenBytes = 16 << 10

// CheckUpstreamURL accepts an https URL, or an http URL whose host is a
// loopback address or localhost: a bearer token is never sent in clear text
// off the host.
func CheckUpstreamURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream URL: %w", err)
	}
	if u.User != nil {
		return nil, errors.New("upstream URL: user information is not allowed; use the token variable")
	}
	if u.Host == "" {
		return nil, errors.New("upstream URL: no host")
	}
	if u.Fragment != "" {
		return nil, errors.New("upstream URL: fragment is not allowed")
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		h := u.Hostname()
		if strings.EqualFold(h, "localhost") {
			return u, nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return u, nil
		}
		return nil, fmt.Errorf("upstream URL: http is allowed only to a loopback host, not %q", h)
	default:
		return nil, fmt.Errorf("upstream URL: scheme %q is not http or https", u.Scheme)
	}
}

// StaticToken is a TokenSource with one fixed bearer token. A 401 cannot be
// recovered by refreshing it.
type StaticToken string

// Token implements TokenSource.
func (t StaticToken) Token(context.Context) (string, error) {
	if t == "" {
		return "", errors.New("no upstream token")
	}
	return string(t), nil
}

// Invalidate implements TokenSource; a static token has nothing to drop.
func (StaticToken) Invalidate() {}

// UpstreamToken reads the bearer token from the environment: the value of
// UpstreamTokenEnv, or the content of the file UpstreamTokenFileEnv names
// (surrounding white space removed). Exactly one must be set.
func UpstreamToken(getenv func(string) string) (StaticToken, error) {
	v, f := getenv(UpstreamTokenEnv), getenv(UpstreamTokenFileEnv)
	switch {
	case v != "" && f != "":
		return "", fmt.Errorf("set only one of %s and %s", UpstreamTokenEnv, UpstreamTokenFileEnv)
	case v != "":
		return StaticToken(strings.TrimSpace(v)), nil
	case f != "":
		fh, err := os.Open(f) //nolint:gosec // path delivered by the Secret Broker
		if err != nil {
			return "", fmt.Errorf("%s: %w", UpstreamTokenFileEnv, err)
		}
		defer fh.Close()
		b, err := io.ReadAll(io.LimitReader(fh, maxUpstreamTokenBytes+1))
		if err != nil {
			return "", fmt.Errorf("%s: %w", UpstreamTokenFileEnv, err)
		}
		if len(b) > maxUpstreamTokenBytes {
			return "", fmt.Errorf("%s: token file larger than %d bytes", UpstreamTokenFileEnv, maxUpstreamTokenBytes)
		}
		t := strings.TrimSpace(string(b))
		if t == "" {
			return "", fmt.Errorf("%s: empty token file", UpstreamTokenFileEnv)
		}
		return StaticToken(t), nil
	default:
		return "", fmt.Errorf("no upstream token: set %s or %s", UpstreamTokenEnv, UpstreamTokenFileEnv)
	}
}

// upstreamHTTPClient never follows redirects: the bearer token is for the
// configured endpoint only, and a redirect is reported as an error.
func upstreamHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil, // loopback upstreams must not go through a proxy from the environment
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
			MaxIdleConns:          4,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// runUpstream relays stdin and stdout to an upstream Streamable HTTP
// endpoint with a static bearer token.
func runUpstream(ctx context.Context, rawURL string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, verbose bool) int {
	u, err := CheckUpstreamURL(rawURL)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-stdio:", err)
		return 2
	}
	tok, err := UpstreamToken(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-stdio:", err)
		return 2
	}
	h := upstreamHTTPClient()
	defer h.CloseIdleConnections()
	r := &Relay{URL: u.String(), HTTP: h, Tokens: tok, In: stdin, Out: stdout, Log: relayLogger(stderr, verbose), Upstream: true}
	if err := r.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "smcp-stdio:", err)
		return 1
	}
	return 0
}
