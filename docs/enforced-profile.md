# Enforced profile on Linux

This guide installs the Secure MCP Gateway in the Enforced profile on a Linux host: smcpd runs as a systemd service under the `smcp-core` identity, every backend MCP server runs in a rootless Podman container, servers that need the network reach it only through the Egress Broker, and smcpd itself is confined by an AppArmor profile. [sandbox.md](sandbox.md) is the reference for the container profile and the `[runtime]` keys; [egress.md](egress.md) for grants.

Every step below runs in CI on GitHub's `ubuntu-24.04` runner (Podman 4.9, crun, slirp4netns, nftables, systemd, AppArmor): job `linux-integration` (`scripts/ci-integration.sh`, enforced section, and `scripts/ci-systemd.sh`) and job `hostile` (the Appendix L suite with `SMCP_HOSTILE_PROFILE=enforced`).

## 1. Host requirements

| Requirement | Package (Ubuntu 24.04) |
|---|---|
| Linux 6.8 or later, x86_64 or arm64, cgroup v2, systemd | base system |
| Rootless Podman with crun | `podman crun uidmap` |
| nftables | `nftables` |
| slirp4netns (only for servers with `network = "egress"`) | `slirp4netns` |
| `nsenter` | `util-linux` |
| AppArmor or SELinux | `apparmor` (with `apparmor_parser`) |

```
sudo apt-get install -y podman crun uidmap nftables slirp4netns apparmor
```

## 2. Install the packaging

```
sudo packaging/linux/install-enforced.sh --check
sudo packaging/linux/install-enforced.sh --bin-dir ./build/bin
```

`--check` verifies the prerequisites and changes nothing. The second command creates the CP-46 identities (`smcp-core`, `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data`, `smcp-console`, `smcp-srv`), their subordinate ID ranges, the CP-46 directories, the nftables table `inet smcp`, the AppArmor profile `smcpd` (loaded in enforce mode when AppArmor is enabled) and the units `smcp-nftables.service` and `smcpd.service`, and copies `smcpd`, `smcpctl` and `smcp-refserver` into `/usr/local/bin`. A second run prints only `present` lines (and `skipped` for the AppArmor profile on a host without AppArmor). Build `smcp-refserver` and any server executable that runs without an image with `CGO_ENABLED=0`: it runs in an empty root directory.

## 3. Bootstrap and configure

```
sudo -u smcp-core smcpctl bootstrap --dir /var/lib/smcp/state/gw \
  --admin-password-file admin.pw --approver-password-file approver.pw --notify off
```

The password files must be readable by `smcp-core`. Copy `/var/lib/smcp/state/gw/smcp.toml` to `/etc/smcp/smcp.toml` (owner `root:smcp`, mode 0640). Relative paths in it resolve against `/etc/smcp`, so make them absolute:

```toml
[state]
dir = "/var/lib/smcp/state/gw/state"

[policy]
file = "/var/lib/smcp/state/gw/policy.json"

[profile]
mode = "enforced"

[runtime]
sandbox = "podman"
cgroup_manager = "cgroupfs"

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = "/srv/projects"     # the reference server's sandbox directory
```

Mount sources must not be in `/var/lib/smcp`, `/etc`, `/run` or the state directory (sandbox.md, "Mount grants"); `/srv` works with the shipped AppArmor profile. Check the host as the service identity:

```
sudo -u smcp-core smcpctl runtime doctor --config /etc/smcp/smcp.toml
```

## 4. Start and check

```
sudo systemctl start smcpd
sudo -u smcp-core smcpctl health --config /etc/smcp/smcp.toml
```

`health` reports `"profile": "enforced"` and `"launcher": "podman"`. `sudo -u smcp-core XDG_RUNTIME_DIR=/run/smcp podman ps` lists one container per server, named `smcp-<alias>-<id>`. `systemctl stop smcpd` runs the shutdown sequence for each container; `smcpctl journal verify` afterwards checks the evidence chain.

### What smcpd.service sets

| Setting | Why |
|---|---|
| `User=smcp-core`, `Group=smcp` | The CP-46 core identity; rootless Podman runs as this user |
| `Delegate=yes`, `DelegateSubgroup=supervisor` | smcpd lives in the leaf `supervisor`; containers get cgroups next to it, inside the service's delegated subtree |
| `Environment=XDG_RUNTIME_DIR=/run/smcp`, `RuntimeDirectory=smcp` | Podman's runtime directory without a systemd user session |
| `ProtectSystem=strict`, `ReadWritePaths=/var/lib/smcp /run/smcp /var/log/smcp`, `ProtectHome=read-only`, `PrivateTmp=yes` | Filesystem confinement of the daemon |
| `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`, `LockPersonality`, `RestrictRealtime`, `RestrictAddressFamilies`, `SystemCallArchitectures=native` | Kernel and process hardening that rootless Podman tolerates |
| `AppArmorProfile=-smcpd` | The shipped AppArmor profile; ignored where it is not loaded |

systemd does not enable controllers for the children of a delegated subtree. With `cgroup_manager = "cgroupfs"`, smcpd writes `+cpu +memory +pids` to its service cgroup's `cgroup.subtree_control` at startup (only in a cgroup owned by its own user), so the container cgroups have memory, PID and CPU limits; the `cgroup-delegation` doctor check runs `podman --cgroup-manager=cgroupfs info` and sees the same controllers the containers get. The unit file lists the hardening options it does not set and why (setuid ID-map helpers, Podman's namespaces).

## 5. AppArmor

`packaging/linux/apparmor/smcpd` confines `/usr/local/bin/smcpd`: read `/etc/smcp`, read and write `/var/lib/smcp`, `/run/smcp` and `/var/log/smcp`, read cgroup and kernel settings for the doctor and the Runtime Monitor, read `/srv`, and execute only Podman (`PUx`: Podman's own profile when the host has one, unconfined otherwise, because rootless Podman needs user namespaces, mounts and the setuid ID-map helpers). Mount sources outside `/srv` go into `/etc/apparmor.d/local/smcpd`:

```
/data/projects/** r,
```

then `sudo apparmor_parser -r /etc/apparmor.d/smcpd`. `cat /proc/$(systemctl show -p MainPID --value smcpd)/attr/current` prints `smcpd (enforce)`. Denials appear in `journalctl -k -g apparmor`.

No profile is shipped for the server containers. Podman applies its default container profile where it can; `[runtime] apparmor_profile` passes another one with `--security-opt apparmor=`. The container profile of [sandbox.md](sandbox.md) (no capabilities, seccomp, user namespace, read-only root, no network or a confined one) applies either way.

## 6. Servers that need the network

```toml
[egress]
enabled = true

[[egress.grant]]
server = "web"
host = "api.example.com"
ports = [443]
methods = ["CONNECT-TLS"]

[[runtime.server]]
alias = "web"
network = "egress"
```

The instance runs on slirp4netns. Before its process starts, smcpd installs an nftables table in the container's network namespace (through `podman unshare nsenter`) that drops everything except TCP to the instance's own Egress Broker listeners, which the instance reaches at 10.0.2.2 through `HTTP_PROXY`, `HTTPS_PROXY` and endpoint variables. Direct connections, DNS included, fail; the broker resolves names and applies the grants. Details: sandbox.md, "Egress".

## 7. What is not covered

- The separate `smcp-srv` identity of CP-46 is created but servers run under `smcp-core`'s rootless Podman (sandbox.md, "Limits").
- No AppArmor or SELinux profile for the server containers beyond Podman's defaults; no SELinux policy module for smcpd.
- FR-13.5 names an install command of smcpctl; the Enforced installation is `packaging/linux/install-enforced.sh`, which does not bootstrap or write `smcp.toml`.
- Writable mount grants outside `/var/lib/smcp` need `ReadWritePaths=` in a drop-in of smcpd.service (and, outside `/srv`, a read rule in the local AppArmor include).
