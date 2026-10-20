package bundle

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// The bundled instance's network (SRS FR-22.24, FR-22.26, FR-22.40,
// SR-4.5-4, SR-4.7-3).
//
// The instance reaches hosted servers only through the hosted listener of
// the Egress Broker (egress.Hosted), which the Connector opens on the host
// before the instance starts. HostAccess says where that listener binds
// and which address the instance uses for it:
//
//   - Podman: the container runs on slirp4netns with host loopback
//     allowed, so the listener binds 127.0.0.1 and the instance reaches it
//     at 10.0.2.2, the slirp4netns host address (as the E-16 sandbox does
//     for servers with egress).
//   - Docker on Linux: the container is on the default bridge, so the
//     listener binds the bridge's gateway address, which the instance
//     uses.
//   - Docker Desktop (macOS, Windows): the listener binds 127.0.0.1 and
//     the instance uses the address host.docker.internal has inside the
//     image, which Docker Desktop forwards to the host's loopback.
//
// The instance's SSRF allowlist (FR-22.27) is that one address.
//
// In the Enforced profile (FR-22.24) the instance is a rootless Podman
// container with its own user namespace (userns=auto, so its own host
// UIDs), and before its process starts an nftables table in its network
// namespace drops every packet except loopback, the replies to accepted
// connections, connections to its own listener, and TCP to the hosted
// listener: no DNS, no Internet, no LAN, no other host service.

// ContainmentTable is the nftables table of the instance's namespace in
// the Enforced profile.
const ContainmentTable = "smcp_contextforge"

// slirpNetwork is the Podman network of the instance.
const slirpNetwork = "slirp4netns:allow_host_loopback=true"

var slirpHost = netip.MustParseAddr("10.0.2.2")

// HostAccess is where the hosted listener binds and how the instance
// reaches it.
type HostAccess struct {
	// Listen is the host address the listener binds.
	Listen netip.Addr
	// Guest is the address the instance uses for it (Listen when the
	// zero value).
	Guest netip.Addr
}

// Target is the address the instance uses.
func (h HostAccess) Target() netip.Addr {
	if h.Guest.IsValid() {
		return h.Guest
	}
	return h.Listen
}

// SSRFAllowed is the instance's SSRF allowlist: the target address only.
func (h HostAccess) SSRFAllowed() []string {
	a := h.Target()
	if !a.IsValid() {
		return nil
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return []string{netip.PrefixFrom(a, bits).String()}
}

// HostAccess returns where the hosted listener binds for this instance's
// engine. The answer is computed once.
func (i *Instance) HostAccess(ctx context.Context) (HostAccess, error) {
	i.mu.Lock()
	if i.access.Listen.IsValid() {
		a := i.access
		i.mu.Unlock()
		return a, nil
	}
	i.mu.Unlock()
	var a HostAccess
	switch {
	case i.o.Engine.Podman:
		a = HostAccess{Listen: netip.MustParseAddr("127.0.0.1"), Guest: slirpHost}
	case runtime.GOOS == "linux":
		out, err := i.engine(ctx, nil, "network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}")
		if err != nil {
			return a, fmt.Errorf("bundle: the default bridge network: %w: %s", err, out)
		}
		for _, f := range strings.Fields(out) {
			if ip, err := netip.ParseAddr(f); err == nil && ip.Is4() {
				a = HostAccess{Listen: ip}
				break
			}
		}
		if !a.Listen.IsValid() {
			return a, fmt.Errorf("bundle: the default bridge network has no IPv4 gateway (%q)", out)
		}
	default:
		py := "import socket\nprint(sorted({x[4][0] for x in socket.getaddrinfo('host.docker.internal',None,socket.AF_INET)})[0])"
		out, err := i.engine(ctx, nil, "run", "--rm", "--network", "bridge", "--entrypoint", "python3", i.o.Image, "-c", py)
		if err != nil {
			return a, fmt.Errorf("bundle: host.docker.internal is not resolvable in this engine: %w: %s", err, out)
		}
		fields := strings.Fields(out)
		if len(fields) == 0 {
			return a, fmt.Errorf("bundle: host.docker.internal has no address in this engine")
		}
		ip, err := netip.ParseAddr(fields[len(fields)-1])
		if err != nil {
			return a, fmt.Errorf("bundle: host.docker.internal: %w", err)
		}
		a = HostAccess{Listen: netip.MustParseAddr("127.0.0.1"), Guest: ip}
	}
	i.mu.Lock()
	i.access = a
	i.mu.Unlock()
	return a, nil
}

// SetSSRFAllowed sets the SSRF allowlist of the next start (FR-22.27).
func (i *Instance) SetSSRFAllowed(nets []string) {
	i.mu.Lock()
	i.o.Settings.SSRFAllowed = append([]string(nil), nets...)
	i.mu.Unlock()
}

// SetEgressAllow sets the hosted listener the Enforced containment admits
// (FR-22.24, SR-4.5-4); a start in the Enforced profile without it is
// refused.
func (i *Instance) SetEgressAllow(ap netip.AddrPort) {
	i.mu.Lock()
	i.egressAllow = ap
	i.mu.Unlock()
}

// Enforced reports whether the instance runs under the Enforced
// containment.
func (i *Instance) Enforced() bool { return i.o.Enforced }

// networkArgs are the engine flags of the instance's network and user
// namespace.
func (i *Instance) networkArgs() []string {
	switch {
	case i.o.Enforced:
		return []string{"--network", slirpNetwork, "--userns=auto"}
	case i.o.Engine.Podman:
		return []string{"--network", slirpNetwork, "--userns=keep-id:uid=10001,gid=10001"}
	}
	return nil
}

// ContainmentRules returns the nftables script of the Enforced
// containment: only loopback, replies, the listener and the hosted
// listener allow.
func ContainmentRules(allow netip.AddrPort) (string, error) {
	a := allow.Addr().Unmap()
	if !a.IsValid() || allow.Port() == 0 {
		return "", errors.New("bundle: the Enforced containment needs the hosted listener's address")
	}
	fam := "ip"
	if a.Is6() {
		fam = "ip6"
	}
	var b strings.Builder
	b.WriteString("table inet " + ContainmentTable + " {\n")
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n")
	b.WriteString("\t\toifname \"lo\" accept\n\t\tct state established,related accept\n")
	fmt.Fprintf(&b, "\t\t%s daddr %s tcp dport %d accept\n", fam, a, allow.Port())
	b.WriteString("\t\treject with icmpx admin-prohibited\n\t}\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n\t\tct state established,related accept\n")
	fmt.Fprintf(&b, "\t\ttcp dport %d accept\n\t}\n}\n", ContainerPort)
	return b.String(), nil
}

// hostTool returns the absolute path of a host tool, looking in PATH and
// then in the system directories a service PATH may lack.
func hostTool(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		if a, err := filepath.Abs(p); err == nil {
			return a
		}
	}
	for _, d := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return name
}

// startEnforced creates and initializes the container, confines its
// network namespace and only then starts its process. Any failure removes
// the container: the start fails closed.
func (i *Instance) startEnforced(ctx context.Context, vals map[string]string, create []string) (err error) {
	i.mu.Lock()
	allow := i.egressAllow
	i.mu.Unlock()
	rules, err := ContainmentRules(allow)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = i.remove(context.WithoutCancel(ctx))
			err = fmt.Errorf("enforced containment of the bundled instance: %w", err)
		}
	}()
	if out, err := i.engine(ctx, vals, append([]string{"create"}, create...)...); err != nil {
		return fmt.Errorf("create: %w: %s", err, out)
	}
	if out, err := i.engine(ctx, nil, "init", i.o.Name); err != nil {
		return fmt.Errorf("init: %w: %s", err, out)
	}
	ns, err := i.engine(ctx, nil, "inspect", "--type", "container", "--format", "{{.NetworkSettings.SandboxKey}}", i.o.Name)
	if err != nil {
		return fmt.Errorf("inspect: %w: %s", err, ns)
	}
	ns = strings.TrimSpace(ns)
	if !filepath.IsAbs(ns) {
		return fmt.Errorf("the container has no network namespace path (got %q)", ns)
	}
	nsenter, nft := hostTool("nsenter"), hostTool("nft")
	if out, err := i.execStdin(ctx, rules, "unshare", nsenter, "--net="+ns, nft, "-f", "-"); err != nil {
		return fmt.Errorf("install the rules in %s: %w: %s", ns, err, out)
	}
	out, err := i.engine(ctx, nil, "unshare", nsenter, "--net="+ns, nft, "list", "table", "inet", ContainmentTable)
	if err != nil {
		return fmt.Errorf("read back the rules: %w: %s", err, out)
	}
	if !strings.Contains(out, "policy drop") || !strings.Contains(out, "dport "+strconv.Itoa(int(allow.Port()))) {
		return fmt.Errorf("the rules were not installed as written: %s", out)
	}
	if out, err := i.engine(ctx, nil, "start", i.o.Name); err != nil {
		return fmt.Errorf("start: %w: %s", err, out)
	}
	return nil
}

// runEngineStdin runs the engine with stdin and a minimal environment.
func (i *Instance) runEngineStdin(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, i.o.Engine.Path, args...) //nolint:gosec // G204: the configured engine binary; arguments built here
	env := []string{}
	for _, k := range []string{"PATH", "HOME", "XDG_RUNTIME_DIR", "CONTAINER_HOST", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
