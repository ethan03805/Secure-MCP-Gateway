package adapter

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// Experimental upstream relay (ContextForge spike, docs/contextforge-spike.md).
//
// The Gateway now reaches Streamable HTTP servers itself: a [[server]] with
// url uses the southbound transport (internal/southbound, FR-5.28 to
// FR-5.30). This bridge, a command-launched backend that runs
//
//	smcp-stdio --experimental-upstream http://127.0.0.1:4444/servers/<id>/mcp
//
// is kept for configurations written during the spike and may be removed.
// The bearer token is delivered by the Secret Broker in UpstreamTokenEnv
// (S4) or as a file named by UpstreamTokenFileEnv (S2, S3); the URL and
// token rules are the southbound transport's. It is not part of any
// requirement.

// UpstreamTokenEnv carries the upstream bearer token.
const UpstreamTokenEnv = southbound.TokenEnv

// UpstreamTokenFileEnv names a file holding the upstream bearer token.
const UpstreamTokenFileEnv = southbound.TokenFileEnv

// CheckUpstreamURL accepts an https URL, or an http URL whose host is a
// loopback address or localhost (southbound.CheckURL).
func CheckUpstreamURL(raw string) (*url.URL, error) { return southbound.CheckURL(raw) }

// StaticToken is a TokenSource with one fixed bearer token. A 401 cannot be
// recovered by refreshing it.
type StaticToken = southbound.StaticToken

// UpstreamToken reads the bearer token from the environment: the value of
// UpstreamTokenEnv, or the content of the file UpstreamTokenFileEnv names
// (surrounding white space removed). Exactly one must be set.
func UpstreamToken(getenv func(string) string) (StaticToken, error) {
	tok, err := southbound.TokenFromEnv(getenv)
	if err != nil {
		return "", err
	}
	if tok == "" {
		return "", fmt.Errorf("no upstream token: set %s or %s", UpstreamTokenEnv, UpstreamTokenFileEnv)
	}
	return StaticToken(tok), nil
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
