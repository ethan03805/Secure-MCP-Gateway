package bundle

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// EscapeProbe runs inside the bundled instance's container to check the
// Enforced containment (FR-22.24, SR-4.5-4, SR-4.7-3, hostile row HFC-12).
// Its arguments are triples "<check> <host> <port>" of TCP connections to
// try; each line it prints is "<check> <ok|blocked|error>": the
// connections (a short timeout, so a dropped packet reads as blocked), a
// write outside the volume, setuid, and the engine and bus sockets, host
// processes and host devices.
const EscapeProbe = `
import os, socket, sys
def tcp(name, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, int(port)))
        print(name, "ok")
    except Exception as e:
        print(name, "blocked", type(e).__name__)
    finally:
        s.close()
args = sys.argv[1:]
for i in range(0, len(args), 3):
    tcp(args[i], args[i+1], args[i+2])
try:
    open("/etc/smcp-escape", "w").write("x")
    print("write_root ok")
except Exception as e:
    print("write_root blocked", type(e).__name__)
try:
    open("/app/data/smcp-probe", "w").write("x")
    os.remove("/app/data/smcp-probe")
    print("write_volume ok")
except Exception as e:
    print("write_volume blocked", type(e).__name__)
try:
    os.setuid(0)
    print("setuid ok")
except Exception as e:
    print("setuid blocked", type(e).__name__)
def unix(p):
    if not os.path.exists(p):
        return "blocked"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(p)
        return "ok"
    except Exception:
        return "blocked"
    finally:
        s.close()
for p in ["/run/podman/podman.sock", "/var/run/docker.sock", "/run/docker.sock", "/run/systemd/private", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
          "/run/user/1000/podman/podman.sock", "/run/user/1001/podman/podman.sock", "/run/user/1000/bus", "/run/user/1001/bus"]:
    print("path:" + p, unix(p))
pids = [d for d in os.listdir("/proc") if d.isdigit()]
print("host_pids", "ok" if len(pids) > 50 else "blocked", len(pids))
devs = sorted(os.listdir("/dev"))
extra = [d for d in devs if d.startswith(("sd", "nvme", "vd", "xvd", "mem", "kmsg", "kvm"))]
print("host_devices", "ok" if extra else "blocked", ",".join(extra))
`

// ProbeInside runs EscapeProbe in container with the engine at engine,
// trying the TCP connections of targets (check name, host, port), and
// returns each check's result and the probe's output.
func ProbeInside(ctx context.Context, engine, container string, targets ...[3]string) (map[string]string, string, error) {
	args := []string{"exec", container, "python3", "-c", EscapeProbe}
	for _, tg := range targets {
		args = append(args, tg[0], tg[1], tg[2])
	}
	out, err := exec.CommandContext(ctx, engine, args...).CombinedOutput() //nolint:gosec // G204: the engine binary; arguments built here
	if err != nil {
		return nil, string(out), fmt.Errorf("probe: %w", err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.Fields(line); len(f) >= 2 {
			got[f[0]] = f[1]
		}
	}
	return got, string(out), nil
}

// Name is the container's name.
func (i *Instance) Name() string { return i.o.Name }
