package config

import (
	"strings"
	"testing"
)

// TestURLServers: a [[server]] reached over Streamable HTTP takes url
// (https, or http to loopback), optionally ca_file and only the token
// slots in secret_env; command-only keys are refused with it (FR-5.28).
func TestURLServers(t *testing.T) {
	withServer := func(body string) string {
		return good + "[[server]]\nalias = \"cf\"\n" + body + "\n"
	}
	cfg, err := Parse([]byte(withServer("url = \"http://127.0.0.1:4444/servers/abc/mcp\"\nca_file = \"ca.pem\"\nsecret_env = { SMCP_UPSTREAM_TOKEN_FILE = \"vault:cf\" }")))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Servers[1]
	if s.URL != "http://127.0.0.1:4444/servers/abc/mcp" || !strings.HasSuffix(s.CAFile, "ca.pem") || s.Command != "" {
		t.Fatalf("%+v", s)
	}
	if _, err := Parse([]byte(withServer(`url = "https://mcp.example.com/mcp"`))); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"http off host":       `url = "http://mcp.example.com/mcp"`,
		"url and command":     "url = \"https://x.example/mcp\"\ncommand = \"/bin/x\"",
		"url and package":     "url = \"https://x.example/mcp\"\npackage = \"x\"",
		"user info":           `url = "https://u:p@x.example/mcp"`,
		"args with url":       "url = \"https://x.example/mcp\"\nargs = [\"a\"]",
		"env with url":        "url = \"https://x.example/mcp\"\nenv = { A = \"b\" }",
		"other secret slot":   "url = \"https://x.example/mcp\"\nsecret_env = { API_KEY = \"vault:k\" }",
		"ca_file without url": "command = \"/bin/x\"\nca_file = \"ca.pem\"",
		"scheme":              `url = "ftp://x.example/mcp"`,
	} {
		if _, err := Parse([]byte(withServer(body))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
