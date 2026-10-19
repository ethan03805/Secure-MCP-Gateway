package bundle

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ReasonWeakCredential: an instance credential is empty, published or
// shorter than MinCredentialChars (FR-22.28).
const ReasonWeakCredential = "CONTEXTFORGE_WEAK_CREDENTIAL"

// MinCredentialChars is the FR-22.28 floor: 43 characters, the base64url
// length of 256 bits.
const MinCredentialChars = 43

// published are values that appear in ContextForge's sources and
// documentation as defaults or examples (CF: .env.example, config.py,
// README). A credential equal to one of them, ignoring case, is refused.
var published = []string{
	"changeme", "my-test-key", "my-test-salt", "admin", "password", "secret",
	"your-secret-key", "my-secret-key", "changeme123", "admin123",
	"my-test-key-but-now-longer-than-32-bytes", "default-secret-key",
}

// Credentials are the five instance credentials (FR-22.28).
type Credentials map[string]string

// NewCredential returns a fresh credential: 256 random bits as base64url
// (43 characters) followed by "Aa1!" so that ContextForge's password
// policy (upper case, lower case, digit, special character) always holds.
// A draw with three sequential characters such as "abc" or "321", which
// that policy refuses, is drawn again.
func NewCredential() (string, error) {
	for {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		v := base64.RawURLEncoding.EncodeToString(b[:]) + "Aa1!"
		if !sequential(v) {
			return v, nil
		}
	}
}

// sequential reports three characters in a row whose codes ascend or
// descend by one.
func sequential(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		d1, d2 := int(s[i+1])-int(s[i]), int(s[i+2])-int(s[i+1])
		if d1 == d2 && (d1 == 1 || d1 == -1) {
			return true
		}
	}
	return false
}

// NewCredentials generates every instance credential.
func NewCredentials() (Credentials, error) {
	c := Credentials{}
	for _, k := range CredentialKeys {
		v, err := NewCredential()
		if err != nil {
			return nil, err
		}
		c[k] = v
	}
	return c, nil
}

// Check refuses credentials that are missing, empty, published or shorter
// than 43 characters, naming the key and never the value.
func (c Credentials) Check() error {
	for _, k := range CredentialKeys {
		v := c[k]
		switch {
		case v == "":
			return packaging.Errf(ReasonWeakCredential, "%s is empty", k)
		case isPublished(v):
			return packaging.Errf(ReasonWeakCredential, "%s equals a value published in ContextForge sources", k)
		case len(v) < MinCredentialChars:
			return packaging.Errf(ReasonWeakCredential, "%s is shorter than %d characters", k, MinCredentialChars)
		}
	}
	return nil
}

func isPublished(v string) bool {
	for _, p := range published {
		if strings.EqualFold(v, p) {
			return true
		}
	}
	return false
}

// AdminToken mints a short-lived administrator token for the admin API
// (I-43) with the instance's JWT key: HS256 with the issuer, audience,
// expiry and JTI that ContextForge requires. Only E-36 holds it.
func AdminToken(c Credentials, now time.Time, ttl time.Duration) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	return SignJWT(c[KeyJWTSecret], map[string]any{
		"sub": AdminEmail, "iss": "mcpgateway", "aud": "mcpgateway-api",
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": base64.RawURLEncoding.EncodeToString(jti),
		"token_use": "session",
	})
}

// SignJWT encodes claims as an HS256 JWT signed with key.
func SignJWT(key string, claims map[string]any) (string, error) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	msg := head + "." + base64.RawURLEncoding.EncodeToString(body)
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}
