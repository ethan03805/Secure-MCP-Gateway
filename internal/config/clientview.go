package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// The client view (CP-46 public/): in the Enforced profile the
// configuration (/etc/smcp, root:smcp 0750) and the state directory
// (smcp-core 0700) are closed to the operator's account, but the desktop
// application and `smcpctl connect` run as that account and need the
// Gateway's addresses and its CA certificate. smcpd therefore publishes, in
// the world-readable directory public/ next to its state directory, a copy
// of the CA trust bundle (ca.crt) and client.json with the addresses below.
// Both are public: the CA certificate is presented in every TLS handshake
// and the addresses are loopback listeners. Nothing secret is written there:
// no password hash, token, key or server configuration.

const (
	// PublicDirName is the client view directory, a sibling of the state
	// directory (/var/lib/smcp/public).
	PublicDirName = "public"
	// ClientViewFile is the client view in that directory.
	ClientViewFile = "client.json"
	// PublicCAFile is the copy of the CA trust bundle in that directory.
	PublicCAFile = "ca.crt"
	// EnforcedPublicDir is the CP-46 client view directory of the Enforced
	// profile.
	EnforcedPublicDir = "/var/lib/smcp/public"
)

// ClientView is the content of client.json.
type ClientView struct {
	// Profile is the configured profile ("enforced").
	Profile string `json:"profile"`
	// MCPURL is the MCP endpoint clients connect to (ResourceURI).
	MCPURL string `json:"mcp_url"`
	// ListenerAddress, PublicURL and MCPPath are the harness listener's
	// settings, from which smcpctl derives the client's allowed origins.
	ListenerAddress string `json:"listener_address"`
	PublicURL       string `json:"public_url"`
	MCPPath         string `json:"mcp_path"`
	// AdminURL is the admin listener (CP-03), for the console window.
	AdminURL string `json:"admin_url"`
	// MetricsAddress is the metrics endpoint (CP-51), empty when off.
	MetricsAddress string `json:"metrics_address,omitempty"`
	// RemotePublicURL is the configured Remote Access URL, if any.
	RemotePublicURL string `json:"remote_public_url,omitempty"`
	// CAFile is the published CA bundle (ca.crt in the same directory).
	CAFile string `json:"ca_file"`
}

// PublicDir returns the client view directory of this configuration, or ""
// when it publishes none: only the Enforced profile does, because in the
// Standalone profiles the user owns the configuration and the state.
func (c *Config) PublicDir() string {
	if c.Profile.Mode != "enforced" || c.State.Dir == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(filepath.Clean(c.State.Dir)), PublicDirName)
}

// ClientView returns the view published in dir.
func (c *Config) ClientView(dir string) ClientView {
	v := ClientView{
		Profile:         c.Profile.Mode,
		MCPURL:          c.ResourceURI(),
		ListenerAddress: c.Listener.Address,
		PublicURL:       c.Listener.PublicURL,
		MCPPath:         c.Listener.MCPPath,
		AdminURL:        c.AdminURL(),
		RemotePublicURL: c.Remote.PublicURL,
		CAFile:          filepath.Join(dir, PublicCAFile),
	}
	if c.Metrics.Enabled {
		v.MetricsAddress = c.Metrics.Address
	}
	return v
}

// LoadClientView reads client.json from dir and checks that it names an
// MCP endpoint and a CA file.
func LoadClientView(dir string) (*ClientView, error) {
	p := filepath.Join(dir, ClientViewFile)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var v ClientView
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if v.MCPURL == "" || v.ListenerAddress == "" || v.CAFile == "" || !filepath.IsAbs(v.CAFile) {
		return nil, fmt.Errorf("%s: incomplete client view (mcp_url, listener_address and an absolute ca_file are required)", p)
	}
	return &v, nil
}

// Config returns the part of a configuration the view carries, for the
// commands that only need the client-facing settings (client setup). The
// state directory is the published directory's sibling, which the caller
// cannot read; State.Dir is set so that the paths client setup protects
// still name it.
func (v *ClientView) Config(dir string) *Config {
	c := &Config{}
	c.Profile.Mode = v.Profile
	c.Listener.Address = v.ListenerAddress
	c.Listener.PublicURL = v.PublicURL
	c.Listener.MCPPath = v.MCPPath
	c.Remote.PublicURL = v.RemotePublicURL
	c.State.Dir = filepath.Join(filepath.Dir(filepath.Clean(dir)), "state")
	c.Dir = filepath.Dir(filepath.Clean(dir))
	return c
}
