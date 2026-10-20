package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Admin is the Connector's client of the bundled instance's admin API
// (I-43). It issues only the operations FR-22.38 allows: users, teams,
// gateways, virtual servers, tokens, health, and the reads reconciliation
// needs.
type Admin struct {
	Base string
	// AdminToken returns a short-lived platform-administrator token; it
	// is used only on admin routes (SR-2.10-2).
	AdminToken func() (string, error)
	HTTP       *http.Client
}

// APIError is an admin API refusal.
type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("contextforge %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// Call sends one request with token (the administrator's when token is
// "", none when it is "-") and decodes a JSON answer into out when out is
// not nil. ContextForge's SQLite store refuses a write now and then while
// another statement runs ("database is locked", "SQL statements in
// progress"); such a refusal is rolled back and the request is sent again,
// at most five times.
func (a *Admin) Call(ctx context.Context, method, path, token string, in, out any) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if err = a.call(ctx, method, path, token, in, out); !transient(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(200*(attempt+1)) * time.Millisecond):
		}
	}
	return err
}

func transient(err error) bool {
	var api *APIError
	return err != nil && asAPI(err, &api) && (strings.Contains(api.Body, "OperationalError") || strings.Contains(api.Body, "database is locked"))
}

func (a *Admin) call(ctx context.Context, method, path, token string, in, out any) error {
	if token == "" {
		t, err := a.AdminToken()
		if err != nil {
			return err
		}
		token = t
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, body)
	if err != nil {
		return err
	}
	if token != "-" { // "-": an unauthenticated request (login)
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := a.HTTP
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		b := string(raw)
		if len(b) > 400 {
			b = b[:400]
		}
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: b}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("contextforge %s %s: %w", method, path, err)
		}
	}
	return nil
}

// CreateUser creates a non-admin user (FR-22.29) with the administrator
// token.
func (a *Admin) CreateUser(ctx context.Context, email, password, fullName string) error {
	return a.Call(ctx, http.MethodPost, "/v1/auth/email/admin/users", "", map[string]any{
		"email": email, "password": password, "full_name": fullName, "is_admin": false, "is_active": true,
		"password_change_required": false}, nil)
}

// EnsureUser creates a package user, or, when ContextForge already has it
// (it keeps users that once held tokens, so an earlier registration or
// probe leaves them deactivated), reactivates it with the given password.
func (a *Admin) EnsureUser(ctx context.Context, email, password, fullName string) error {
	err := a.CreateUser(ctx, email, password, fullName)
	var api *APIError
	if err == nil || !asAPI(err, &api) || api.Status != http.StatusConflict {
		return err
	}
	upd := map[string]any{"is_active": true, "is_admin": false, "password_change_required": false, "password": password}
	if err := a.Call(ctx, http.MethodPatch, "/v1/auth/email/admin/users/"+pathEscape(email), "", upd, nil); err != nil {
		// The same password again can be refused as a reuse; then only
		// reactivate.
		delete(upd, "password")
		return a.Call(ctx, http.MethodPatch, "/v1/auth/email/admin/users/"+pathEscape(email), "", upd, nil)
	}
	return nil
}

// RemoveUser deletes a user, or deactivates it when ContextForge keeps it
// for the tokens it held.
func (a *Admin) RemoveUser(ctx context.Context, email string) error {
	err := a.Call(ctx, http.MethodDelete, "/v1/auth/email/admin/users/"+pathEscape(email), "", nil, nil)
	var api *APIError
	if err != nil && asAPI(err, &api) && api.Status == http.StatusConflict {
		return a.Call(ctx, http.MethodPatch, "/v1/auth/email/admin/users/"+pathEscape(email), "", map[string]any{"is_active": false}, nil)
	}
	return err
}

// Login returns a session token for a user.
func (a *Admin) Login(ctx context.Context, email, password string) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := a.Call(ctx, http.MethodPost, "/v1/auth/email/login", "-", map[string]any{"email": email, "password": password}, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("contextforge login of %s returned no token", email)
	}
	return out.AccessToken, nil
}

// pathEscape escapes one path segment.
func pathEscape(s string) string { return url.PathEscape(s) }
