package main

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestLabelWithMode: smcpctl health and version print the installation mode
// after the release label on Windows and in WSL (SR-4-2).
func TestLabelWithMode(t *testing.T) {
	reqtest.Partial(t, "SR-4-2")
	if got := labelWithMode("not enforced", "windows-user"); got != "not enforced, windows-user" {
		t.Fatal(got)
	}
	if got := labelWithMode("enforced", ""); got != "enforced" {
		t.Fatal(got)
	}
}
