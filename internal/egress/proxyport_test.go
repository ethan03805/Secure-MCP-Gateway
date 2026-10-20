package egress

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAttachFixedProxyPort: for a Windows AppContainer, whose WFP filters
// let it reach one loopback port, the broker serves the instance's proxy on
// that port, binds no destination endpoints, and reports the attachment as
// enforced; the wrapping launcher asks for it from the spec (FR-21.14).
// Partial: the filters themselves are tested on Windows in
// internal/winsandbox.
func TestAttachFixedProxyPort(t *testing.T) {
	reqtest.Partial(t, "FR-21.14")
	h := newHarness(t, []Grant{{Server: "web", Host: "example.com", Ports: []int{443}, Methods: []string{"GET"}, EndpointEnv: "X_URL"}}, Limits{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	att, err := h.b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web",
		Network: &pipeline.EgressNetwork{ListenAddr: netip.MustParseAddr("127.0.0.1"), LauncherConfines: true, ProxyPort: port}})
	if err != nil {
		t.Fatal(err)
	}
	defer att.Close()
	want := "127.0.0.1:" + strconv.Itoa(int(port))
	if !att.Enforced || len(att.Allow) != 1 || att.Allow[0].String() != want || !strings.Contains(att.Env["HTTPS_PROXY"], want) {
		t.Fatalf("attachment %+v", att)
	}
	if _, ok := att.Env["X_URL"]; ok {
		t.Fatalf("destination endpoint bound beside the fixed proxy port: %v", att.Env)
	}

	// The wrapping launcher passes the spec's port.
	var got pipeline.EgressRequest
	l := &attachingLauncher{inner: &captureLauncher{}, att: attacherFunc(func(_ context.Context, r pipeline.EgressRequest) (*pipeline.EgressAttachment, error) {
		got = r
		return &pipeline.EgressAttachment{Close: func() error { return nil }}, nil
	})}
	p, err := l.Launch(context.Background(), pipeline.ServerSpec{Alias: "web", EgressProxyPort: 4242})
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if got.Network == nil || got.Network.ProxyPort != 4242 || !got.Network.LauncherConfines {
		t.Fatalf("request %+v", got)
	}
}

type attacherFunc func(context.Context, pipeline.EgressRequest) (*pipeline.EgressAttachment, error)

func (f attacherFunc) Attach(ctx context.Context, r pipeline.EgressRequest) (*pipeline.EgressAttachment, error) {
	return f(ctx, r)
}
