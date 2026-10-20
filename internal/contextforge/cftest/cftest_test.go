package cftest

import (
	"slices"
	"testing"
)

// TestCIDRs keeps only network lines from an engine's output that starts
// with pull progress, and URL brackets an IPv6 host.
func TestCIDRs(t *testing.T) {
	out := "Unable to find image 'ghcr.io/x@sha256:ab' locally\nsha256:ab: Pulling from x\nDigest: sha256:ab\nStatus: Downloaded newer image\n192.168.65.254/32\nfdc4:f303:9324::254/128\n"
	if got, want := CIDRs(out), []string{"192.168.65.254/32", "fdc4:f303:9324::254/128"}; !slices.Equal(got, want) {
		t.Fatalf("CIDRs = %v, want %v", got, want)
	}
	if got := (Host{Name: "172.17.0.1"}).URL("8080"); got != "http://172.17.0.1:8080/mcp" {
		t.Fatalf("URL = %s", got)
	}
	if got := (Host{Name: "fd00::1"}).URL("80"); got != "http://[fd00::1]:80/mcp" {
		t.Fatalf("URL = %s", got)
	}
}
