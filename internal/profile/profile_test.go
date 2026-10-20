package profile

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	full := Host{OS: "linux", Arch: "amd64", Podman: true, Rootless: true, Nftables: true, CgroupV2: true, Systemd: true}
	mac := Host{OS: "darwin", Arch: "arm64"}

	r, err := Resolve("auto", "subprocess", false, mac)
	if err != nil || r.Profile != Standalone || r.Label != "not enforced" || r.Degraded() != "unconfined" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(strings.Join(r.Reasons, ","), "linux") {
		t.Fatalf("reasons %v", r.Reasons)
	}
	// A capable host with an unconfined launcher is still standalone.
	r, _ = Resolve("auto", "subprocess", false, full)
	if r.Profile != Standalone {
		t.Fatalf("%+v", r)
	}
	r, err = Resolve("auto", "podman", true, full)
	if err != nil || r.Profile != Enforced || r.Degraded() != "" || !r.Confined {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := Resolve("enforced", "subprocess", false, mac); err == nil {
		t.Fatal("enforced mode ran unconfined")
	}
	r, _ = Resolve("standalone", "podman", true, full)
	if r.Profile != Standalone {
		t.Fatalf("%+v", r)
	}
	h := DetectHost()
	if h.OS == "" || h.Arch == "" {
		t.Fatal("host not detected")
	}
}

// TestDegradedOnlyByProfile: only a degraded state whose every cause is the
// profile's own cause ("unconfined" on Standalone) counts (FR-20.2, FR-20.5).
func TestDegradedOnlyByProfile(t *testing.T) {
	std, _ := Resolve("auto", "subprocess", false, Host{OS: "darwin", Arch: "arm64"})
	enf, _ := Resolve("auto", "podman", true, Host{OS: "linux", Arch: "amd64", Podman: true, Rootless: true, Nftables: true, CgroupV2: true, Systemd: true})
	for _, c := range []struct {
		r      Report
		state  string
		causes []string
		want   bool
	}{
		{std, "degraded", []string{"unconfined"}, true},
		{std, "degraded", []string{"unconfined", "unconfined"}, true},
		{std, "degraded", []string{"unconfined", "unverified_manifests"}, false},
		{std, "degraded", []string{"backend_unreachable"}, false},
		{std, "degraded", nil, false},
		{std, "fail-closed", []string{"unconfined", "emergency_stop"}, false},
		{std, "fail-closed", []string{"unconfined"}, false},
		{std, "healthy", []string{"unconfined"}, false},
		{enf, "degraded", []string{"unconfined"}, false},
		{enf, "healthy", nil, false},
	} {
		if got := c.r.DegradedOnlyByProfile(c.state, c.causes); got != c.want {
			t.Errorf("%s %s %v: got %v, want %v", c.r.Profile, c.state, c.causes, got, c.want)
		}
	}
}
