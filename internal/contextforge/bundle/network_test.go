package bundle

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// fakePodman records the engine calls of an Enforced start and answers as
// rootless Podman does; nftOut is what the rules read back as.
type fakePodman struct {
	mu     sync.Mutex
	calls  []string
	stdin  string
	nftOut string
	fail   string // a subcommand that fails
}

func (f *fakePodman) exec(_ context.Context, _ map[string]string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	if args[0] == f.fail {
		return "boom", errors.New("exit status 125")
	}
	switch args[0] {
	case "inspect":
		return "/run/user/1000/netns/netns-abc", nil
	case "unshare":
		return f.nftOut, nil
	}
	return "", nil
}

func (f *fakePodman) execStdin(_ context.Context, stdin string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "stdin "+strings.Join(args, " "))
	f.stdin = stdin
	return "", nil
}

func enforcedInstance(t *testing.T, f *fakePodman) *Instance {
	t.Helper()
	creds, _ := NewCredentials()
	in, err := New(Options{Engine: Engine{Path: "podman", Podman: true}, Enforced: true, Image: "ghcr.io/ibm/mcp-context-forge@sha256:" + strings.Repeat("a", 64),
		Name: "smcp-cf-enf", Settings: Settings{Limits: testLimits}, Credentials: func() (Credentials, error) { return creds, nil }})
	if err != nil {
		t.Fatal(err)
	}
	in.exec, in.execStdin = f.exec, f.execStdin
	return in
}

// TestEnforcedStart: in the Enforced profile the instance is created and
// initialized, an nftables table that admits only loopback, replies, its
// listener and the hosted listener is installed in its namespace and read
// back, and only then is its process started; it runs on slirp4netns
// with its own user namespace and the hardening flags. A start without
// the hosted listener, or whose rules do not read back, starts nothing
// and removes the container (FR-22.24, SR-4.5-4, SR-4.7-3).
func TestEnforcedStart(t *testing.T) {
	reqtest.Partial(t, "FR-22.24", "SR-4.5-4", "SR-4.7-3")
	if _, err := New(Options{Engine: Engine{Path: "docker"}, Enforced: true, Image: "x@sha256:" + strings.Repeat("a", 64), Name: "n",
		Credentials: func() (Credentials, error) { return nil, nil }}); err == nil {
		t.Fatal("Enforced with Docker accepted")
	}
	allow := netip.MustParseAddrPort("10.0.2.2:41234")
	rules, err := ContainmentRules(allow)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"policy drop", "ip daddr 10.0.2.2 tcp dport 41234 accept", "tcp dport 4444 accept", "reject with icmpx admin-prohibited", "oifname \"lo\" accept"} {
		if !strings.Contains(rules, want) {
			t.Fatalf("rules lack %q:\n%s", want, rules)
		}
	}
	if strings.Count(rules, "accept") != 6 {
		t.Fatalf("rules admit more than loopback, replies, the listener and the hosted listener:\n%s", rules)
	}

	f := &fakePodman{nftOut: "table inet smcp_contextforge { chain output { policy drop; ip daddr 10.0.2.2 tcp dport 41234 accept } }"}
	in := enforcedInstance(t, f)
	if err := in.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "hosted listener") {
		t.Fatalf("start without the hosted listener: %v", err)
	}
	in.SetEgressAllow(allow)
	if err := in.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Stop(context.Background()) })
	f.mu.Lock()
	calls := append([]string(nil), f.calls...)
	stdin := f.stdin
	f.mu.Unlock()
	order := []string{"create ", "init smcp-cf-enf", "inspect --type container", "stdin unshare ", "unshare ", "start smcp-cf-enf"}
	j := 0
	var create string
	for _, c := range calls {
		if j < len(order) && strings.HasPrefix(c, order[j]) {
			if j == 0 {
				create = c
			}
			j++
		}
	}
	if j != len(order) {
		t.Fatalf("calls out of order:\n%s", strings.Join(calls, "\n"))
	}
	if stdin != rules {
		t.Fatalf("installed rules differ:\n%s", stdin)
	}
	for _, flag := range []string{"--network slirp4netns:allow_host_loopback=true", "--userns=auto", "--read-only", "--cap-drop ALL",
		"--security-opt no-new-privileges", "-p 127.0.0.1:", "--memory 1024m", "--pids-limit 256"} {
		if !strings.Contains(create, flag) {
			t.Errorf("create lacks %q: %s", flag, create)
		}
	}
	for _, bad := range []string{"--privileged", "/var/run", "podman.sock", "docker.sock", "--pid=", " --pid ", "--network host", "--device"} {
		if strings.Contains(create, bad) {
			t.Errorf("create has %q: %s", bad, create)
		}
	}
	_ = in.Stop(context.Background())

	// Rules that do not read back: nothing starts, the container goes.
	g := &fakePodman{nftOut: "table inet smcp_contextforge { }"}
	in2 := enforcedInstance(t, g)
	in2.SetEgressAllow(allow)
	if err := in2.Start(context.Background()); err == nil {
		t.Fatal("a start with rules that do not read back succeeded")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last := g.calls[len(g.calls)-1]
	for _, c := range g.calls {
		if strings.HasPrefix(c, "start ") {
			t.Fatalf("the process started: %v", g.calls)
		}
	}
	if !strings.HasPrefix(last, "rm -f smcp-cf-enf") {
		t.Fatalf("the container was not removed: %v", g.calls)
	}
}

// TestHostAccess: Podman's listener binds loopback and the instance uses
// the slirp4netns host address; the SSRF allowlist is that one address.
func TestHostAccess(t *testing.T) {
	reqtest.Partial(t, "FR-22.27", "FR-22.40")
	in := enforcedInstance(t, &fakePodman{})
	a, err := in.HostAccess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Listen.String() != "127.0.0.1" || a.Target().String() != "10.0.2.2" {
		t.Fatalf("access %+v", a)
	}
	if got := a.SSRFAllowed(); len(got) != 1 || got[0] != "10.0.2.2/32" {
		t.Fatalf("SSRF allowlist %v", got)
	}
	if got := (HostAccess{Listen: netip.MustParseAddr("172.17.0.1")}).SSRFAllowed(); got[0] != "172.17.0.1/32" {
		t.Fatalf("bridge allowlist %v", got)
	}
}
