package southbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

// CheckURL accepts the endpoint URL of a Streamable HTTP server: an https
// URL, or an http URL whose host is a loopback address or localhost, so
// that a bearer token or a call's arguments never cross the network in
// clear text. User information and fragments are refused.
func CheckURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	if u.User != nil {
		return nil, errors.New("server URL: user information is not allowed; deliver the token as a secret")
	}
	if u.Host == "" {
		return nil, errors.New("server URL: no host")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, errors.New("server URL: fragment is not allowed")
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if IsLoopbackHost(u.Hostname()) {
			return u, nil
		}
		return nil, fmt.Errorf("server URL: http is allowed only to a loopback host, not %q; use https", u.Hostname())
	default:
		return nil, fmt.Errorf("server URL: scheme %q is not http or https", u.Scheme)
	}
}

// IsLoopbackHost reports whether h is localhost or a loopback address.
func IsLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// TokenEnv carries the bearer token of a Streamable HTTP server: the Secret
// Broker delivers it as an S4 environment value of a slot with this name.
const TokenEnv = "SMCP_UPSTREAM_TOKEN"

// TokenFileEnv names a file holding the bearer token (S2 or S3 delivery).
const TokenFileEnv = "SMCP_UPSTREAM_TOKEN_FILE"

// maxTokenBytes bounds a token read from a file.
const maxTokenBytes = 16 << 10

// TokenFromEnv reads the bearer token from the value of TokenEnv or from
// the file TokenFileEnv names (surrounding white space removed). Neither
// set returns "" (the server takes no credential); both set is an error,
// and so is a token that cannot be a header value.
func TokenFromEnv(getenv func(string) string) (string, error) {
	v, f := getenv(TokenEnv), getenv(TokenFileEnv)
	var tok string
	switch {
	case v != "" && f != "":
		return "", fmt.Errorf("set only one of %s and %s", TokenEnv, TokenFileEnv)
	case v != "":
		tok = strings.TrimSpace(v)
	case f != "":
		fh, err := os.Open(f) //nolint:gosec // path delivered by the Secret Broker
		if err != nil {
			return "", fmt.Errorf("%s: %w", TokenFileEnv, err)
		}
		defer fh.Close()
		b, err := io.ReadAll(io.LimitReader(fh, maxTokenBytes+1))
		if err != nil {
			return "", fmt.Errorf("%s: %w", TokenFileEnv, err)
		}
		if len(b) > maxTokenBytes {
			return "", fmt.Errorf("%s: token file larger than %d bytes", TokenFileEnv, maxTokenBytes)
		}
		tok = strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("%s: empty token file", TokenFileEnv)
		}
	default:
		return "", nil
	}
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; c < 0x21 || c > 0x7e {
			// The value is never quoted: a token with a control character
			// could inject a header line.
			return "", errors.New("the bearer token contains a character that is not visible ASCII")
		}
	}
	return tok, nil
}

// StaticToken is a bearer token that never changes. It implements the
// token source of the Harness Adapter Kit's relay.
type StaticToken string

// Token returns the token.
func (t StaticToken) Token(context.Context) (string, error) {
	if t == "" {
		return "", errors.New("no upstream token")
	}
	return string(t), nil
}

// Invalidate does nothing: a static token cannot be refreshed.
func (StaticToken) Invalidate() {}
