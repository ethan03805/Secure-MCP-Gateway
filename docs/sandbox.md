# Server sandbox (enforced profile)

In the enforced profile the Gateway starts every backend MCP server in a rootless Podman container. Three architecture elements do this:

| Element | Package | What it does |
|---|---|---|
| E-15 Server Runtime Manager | `internal/sandbox` (`Launcher`) | Builds the launch specification of each instance, starts it with an argument vector, keeps the instance table, runs the shutdown sequence, removes containers |
| E-16 Execution Sandbox | `internal/sandbox` (`LaunchSpec.PodmanArgs`) | The container profile: read-only root, no capabilities, no network, cgroup limits, granted mounts only |
| E-17 Runtime Monitor | `internal/sandbox` (`Monitor`) | Samples each instance's cgroup, follows the Podman event stream, records runtime evidence and kills an instance that breaches a limit or matches a kill rule |

On macOS, and on Linux without the prerequisites below, the Gateway runs servers as ordinary child processes (standalone profile, "not enforced"). See [Security Limitations](security-limitations.md).

## Prerequisites

`smcpctl runtime doctor` checks each of these on the current host and prints a remedy for each one that fails. It changes nothing.

| Check ID | Prerequisite |
|---|---|
| `os`, `arch` | Linux on x86_64 or arm64 |
| `kernel` | Kernel 6.8 or later |
| `rootless` | smcpd runs as a non-root user (the service identity `smcp-core`) |
| `cgroup-v2` | cgroup v2 unified hierarchy |
| `userns` | Unprivileged user namespaces enabled |
| `userns-apparmor` | Warning only: `kernel.apparmor_restrict_unprivileged_userns=1` is set; Podman then needs an AppArmor profile that allows user namespaces. If the `podman` check passes, nothing more is needed |
| `subid-subuid`, `subid-subgid` | At least 65,536 subordinate UIDs and GIDs for the user in `/etc/subuid` and `/etc/subgid` |
| `uidmap` | `newuidmap` and `newgidmap` |
| `nftables` | `nft` |
| `systemd` | systemd is the running service manager |
| `lsm` | AppArmor or SELinux is enabled |
| `podman` | `podman info` succeeds as this user |
| `podman-rootless` | Podman runs rootless |
| `crun` | The OCI runtime is `crun` |
| `podman-cgroup-v2` | Podman uses cgroup v2 |
| `cgroup-delegation` | The `memory`, `pids` and `cpu` controllers are delegated to this user |
| `seccomp` | Podman has seccomp |

```
smcpctl runtime doctor [--json] [--podman PATH] [--config FILE]
```

Exit status 0 when every check passes, 1 otherwise. `--json` prints `{"ready": bool, "checks": [{"id", "name", "status", "detail", "remedy"}]}`. `status` is `pass`, `warn` or `fail`. The Go function behind it is `sandbox.Doctor(ctx, sandbox.DoctorOptions{})`; `smcpctl doctor` can call it.

### Startup refusal

When `[runtime] sandbox = "podman"`, smcpd runs the same checks before it launches anything:

- With `[profile] mode = "enforced"`, any failed check stops startup with `enforced-profile prerequisites missing: <each failed check>; run smcpctl runtime doctor for remedies` (FR-13.9).
- With `mode = "auto"`, only the checks the container itself needs stop startup (`os`, `arch`, `kernel`, `rootless`, `cgroup-v2`, `userns`, the two `subid` checks, `uidmap`, every `podman*` check, `crun`, `cgroup-delegation`, `seccomp`). A missing `systemd`, `nftables` or LSM is logged; servers are still sandboxed, but the profile resolves to standalone and the release label is "not enforced".

## Installing on a Linux host

`packaging/linux/install-enforced.sh` prepares the host. Run it as root:

```
sudo packaging/linux/install-enforced.sh --check          # prerequisites only
sudo packaging/linux/install-enforced.sh [--bin-dir DIR] [--start]
```

It verifies every prerequisite first and exits with status 2, listing each missing one, before it changes anything. It then creates, when absent:

| Object | Detail |
|---|---|
| Group | `smcp` |
| Users | `smcp-core`, `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data`, `smcp-console`, `smcp-srv` (system users, no login shell) |
| Subordinate IDs | 65,536 UIDs and GIDs each for `smcp-core` (runs smcpd and rootless Podman) and `smcp-srv`, in non-overlapping ranges starting at 100000 or after the highest existing range |
| Directories | `/etc/smcp` (root:smcp 0750); `/var/lib/smcp/{policy,registry,artifacts}` (smcp-core 0700); `/var/lib/smcp/journal` (smcp-evidence 0700); `/var/lib/smcp/keys` (smcp-keys 0700); `/var/lib/smcp/vault` (smcp-vault 0700); `/var/lib/smcp/exports` (smcp-core 0750); `/var/lib/smcp/state` and `/var/lib/smcp/home/smcp-core` (smcp-core 0700); `/var/log/smcp` (0750) |
| nftables | `/etc/smcp/smcp.nft`, loaded as table `inet smcp` |
| systemd units | `/etc/systemd/system/smcp-nftables.service` and `smcpd.service`, enabled |
| Binaries | With `--bin-dir DIR`: `smcpd`, `smcpctl` and `smcp-refserver` from DIR into `/usr/local/bin` |

Each step prints `present`, `created` or `updated`. A second run prints only `present` lines. It never touches configuration, keys, policy or the journal. `--start` starts both units and needs `/etc/smcp/smcp.toml`.

The Gateway currently keeps keys and the journal in one state directory owned by `smcp-core` (`/var/lib/smcp/state`). The per-identity directories of CP-46 are created for the elements that will use them.

### smcpd.service

The unit runs `/usr/local/bin/smcpd --config /etc/smcp/smcp.toml` as `smcp-core:smcp` with `Delegate=yes` and `DelegateSubgroup=supervisor`, so that container cgroups are created below the service's own cgroup, and with `XDG_RUNTIME_DIR=/run/smcp`. With this unit set `runtime.cgroup_manager = "cgroupfs"`. It applies `ProtectSystem=strict` (writable: `/var/lib/smcp`, `/run/smcp`, `/var/log/smcp`), `ProtectHome=read-only`, `PrivateTmp`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`, `LockPersonality`, `RestrictRealtime`, `RestrictAddressFamilies` and `SystemCallArchitectures=native`. The unit file lists the options it does not set and why (rootless Podman needs setuid `newuidmap`, its own namespaces and capabilities inside them). A writable mount grant outside `/var/lib/smcp` needs a drop-in with `ReadWritePaths=` as well as the grant in `smcp.toml`.

### nftables table `inet smcp`

| Object | Purpose |
|---|---|
| set `gateway_ports` | The harness and control listener ports (8443, 8444 by default; edit `/etc/smcp/smcp.nft` if you change them) |
| chain `input` | Drops TCP connections to `gateway_ports` that do not arrive on loopback |
| chain `egress` | Empty; jumped to from `output`. The Egress Broker (E-18) adds its rules here |

Sandboxed instances have no network interface but loopback (network `none`), so they cannot reach anything whatever this table contains.

## Configuration

The `[runtime]` table of `smcp.toml`. All keys are optional.

| Key | Default | Meaning |
|---|---|---|
| `sandbox` | `"podman"` when `[profile] mode = "enforced"`, else `"none"` | `"podman"` runs servers in containers; `"none"` runs them as child processes. `"podman"` with `mode = "standalone"` is a configuration error |
| `podman` | `podman` on `PATH` | Absolute path of the Podman binary |
| `image` | none | Default image for every server, by digest (`name@sha256:<64 hex>`). Without an image the Gateway uses an empty root directory and mounts the server executable read-only |
| `memory_bytes` | 536870912 (512 MiB, CP-24) | Memory limit; swap is disabled (`--memory-swap` equals the limit). Minimum 16 MiB |
| `cpus` | 1 (CP-24) | CPU limit |
| `pids` | 128 (CP-24) | PID limit (threads count). Minimum 8 |
| `tmpfs_bytes` | 67108864 (64 MiB) | Size of each of the `/work` and `/tmp` tmpfs mounts |
| `nofile` | 1024 | Open-file limit |
| `userns_size` | 2048 | UIDs in each instance's user namespace (1024 to 65536) |
| `user` | `"1000:1000"` | UID:GID inside the container; must be below `userns_size` |
| `apparmor_profile` | none | Passed as `--security-opt apparmor=<name>` |
| `selinux_type` | none | Passed as `--security-opt label=type:<type>` |
| `cgroup_manager` | Podman's default | `"systemd"` or `"cgroupfs"`; use `"cgroupfs"` under `smcpd.service` |
| `monitor_interval` | `"500ms"` | How often the Runtime Monitor samples each cgroup (50ms to 10s) |

Per-server settings, matched by alias. Every `alias` must name a configured `[[server]]`.

```toml
[[runtime.server]]
alias = "fs"
memory_bytes = 268435456   # overrides [runtime]
pids = 64
network = "none"           # or "egress"
scope = "shared"
userns = "auto"            # or "keep-id"
allow_spawn = false
on_deviation = "alert"     # or "kill-instance"

[[runtime.server.mount]]
source = "/srv/projects"   # host path; relative paths are resolved against the config directory
target = "/data"           # path in the container; default: the source path
write = false              # read-only unless true
```

| Key | Default | Meaning |
|---|---|---|
| `image` | `[runtime] image` | Image for this server, by digest. The `[[server]] command` is then a path inside the image |
| `memory_bytes`, `cpus`, `pids` | `[runtime]` values | Resource limits for this server |
| `network` | `"none"` | `"none"`: loopback only. `"egress"` is refused at launch for now: attaching a rootless Podman network namespace to the Egress Broker is not built (see "Limits") |
| `scope` | `"shared"` | Instance scope (FR-5.10). Only `"shared"` (one instance per server) is implemented; `"session"` and `"call"` are refused at load |
| `userns` | `"auto"` | `"auto"` gives each instance its own range of subordinate UIDs. `"keep-id"` maps the Gateway user into the container so that writable grants on directories the Gateway user owns work; instances of that server then share one mapping |
| `allow_spawn` | `false` | Declares that the server may start processes. When false, every process besides the first is a deviation |
| `on_deviation` | `"alert"` | Containment action for a deviation: record it (`alert`) or also kill the instance (`kill-instance`). Resource-limit breaches always kill |
| `mount` | none | Host paths granted to this server |

### Mount grants

A mount source must be an existing, clean absolute path (after resolving relative paths), must not contain `,` `=` or a newline, must not be a socket, and must not be, contain or lie inside the Gateway state directory, `/`, `/proc`, `/sys`, `/dev`, `/boot`, `/etc`, `/root`, `/run`, `/var/run`, `/var/lib/containers`, `/var/lib/docker`, `/var/lib/smcp`, `/etc/smcp` or `/run/smcp`. Names containing `docker.sock`, `podman.sock`, `containerd.sock`, `crio.sock`, `dbus` or `systemd` are refused. A target must not be at or below `/`, `/work`, `/tmp`, `/var/tmp`, `/smcp`, `/proc`, `/sys`, `/dev`, `/run` or `/etc`; choose another path such as `/data`.

With `userns = "auto"` the instance runs under a subordinate UID, not the Gateway user. It can read a granted directory only if the files are readable by others (for example mode 0755 for directories and 0644 for files), and write only to a directory that is writable by others. Files it creates belong to that subordinate UID on the host. Use a dedicated directory for writable grants, or `userns = "keep-id"` for the server.

### Environment

The instance environment is the server's `env` and its resolved `secret_env`. `PATH` and `HOME` of the Gateway are not passed. Values travel in the Podman process environment and are named on the command line (`--env=NAME`), never written there. Names that would configure Podman itself are refused: those starting with `CONTAINERS_`, `PODMAN_`, `BUILDAH_`, `XDG_`, `DBUS_`, `DOCKER_`, `LD_`, `STORAGE_`, `REGISTRY_`, `CONTAINER_`, and `NOTIFY_SOCKET`, `TMPDIR`, `SSL_CERT_*`, the proxy variables, `GODEBUG` and `GOTRACEBACK`.

Secret files (delivery modes S2 and S3, see [secrets.md](secrets.md)) are written by the Secret Broker into a per-instance directory on the host. The sandbox mounts that directory read-only at `/smcp/secrets` and rewrites the file-path variables to match. The files are mode 0600 and belong to the Gateway user, so a server that receives them needs `userns = "keep-id"`; with `"auto"` the launch is refused with a message saying so.

## The sandbox profile

Every instance is started as:

```
podman run --interactive --name smcp-<alias>-<id> --label smcp.managed=1 --label smcp.gateway=<gateway id>
  --label smcp.alias=<alias> --label smcp.instance=<instance id>
  --pull=never --log-driver=none --read-only --read-only-tmpfs=false
  --cap-drop=all --security-opt=no-new-privileges --userns=auto:size=<userns_size>
  --network=none --pid=private --ipc=private --uts=private --hostname=<name> --no-hosts --passwd=false
  --memory=<bytes> --memory-swap=<bytes> --cpus=<n> --pids-limit=<n>
  --ulimit=nofile=<n>:<n> --ulimit=core=0:0
  --tmpfs=/work:rw,nosuid,nodev,size=<bytes>,mode=1777
  --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=<bytes>,mode=1777
  --workdir=/work --user=<uid:gid>
  [--security-opt=apparmor=<profile>] [--security-opt=label=type:<type>] [--cgroup-manager=<manager>]
  --mount=type=bind,src=<source>,dst=<target>,ro|rw,bind-propagation=rprivate ...
  --env=<NAME> ...
  (<image> | --rootfs <state>/runtime/rootfs)  <argv>
```

Podman's default seccomp profile applies (it is never disabled). No device is added and no host namespace is shared. The working directory is `/work` unless the server's `dir` equals a mount target. Without an image, the root directory is `<state>/runtime/rootfs`: empty mount points, a two-line `/etc/passwd`, and the server executable bind-mounted read-only at `/smcp/bin/<name>`. Such a server must be a statically linked executable (for Go: `CGO_ENABLED=0`); servers that need an interpreter need an image.

`smcpctl runtime spec --config FILE` prints, without starting anything, the launch specification and the Podman argument vector of every configured server (FR-5.9). Environment values are not printed.

The launch specification records: alias, instance ID, container name, the artifact (command, `sha256:` digest of the executable or the image digest), argument vector, environment variable names, mounts, network, working directory, limits, sandbox profile and scope.

## Lifecycle

- **Start.** The Gateway removes containers labelled `smcp.managed=1` that belong to an earlier Gateway process, then launches each configured server at startup. It waits until the container runs and its cgroup is known before the first MCP message, so the monitor sees the instance from the start.
- **Shutdown (FR-5.27).** Close stdin, wait 5 seconds, `podman kill --signal TERM`, wait 5 seconds, `podman kill --signal KILL`, then `podman rm --force`. If the Gateway process dies, the attached Podman client is killed with it (parent-death signal), so the instance loses its stdin.
- **Unexpected exit.** Recorded as `instance_exited` with reason `INSTANCE_EXITED_UNEXPECTEDLY` (or `MEMORY_LIMIT`). The next call to the server fails and the instance is then relaunched; later calls reach the new instance. An instance that does not answer a call within `upstream_timeout` is also relaunched (the call ends with `-31009`). A relaunch that fails, or whose tool list differs from the enabled revision, suspends the server.

## Runtime Monitor

For each instance the monitor reads, every `monitor_interval` and on each kernel change notification of `memory.events` and `pids.events` (inotify), the cgroup files `memory.current`, `memory.peak`, `memory.events`, `pids.current`, `pids.peak`, `pids.events`, `cpu.stat` and `cgroup.procs` (including child cgroups). It follows `podman events` for the Gateway's containers.

| Observation | Rule | Action |
|---|---|---|
| `oom_kill` in `memory.events` increased, or a Podman `oom` event | Memory limit breach | Kill the instance |
| Unrequested exit 137 after the cgroup reached 90% of its memory limit or recorded an OOM event | Memory limit breach (rootless Podman does not always report `OOMKilled`) | Recorded at exit |
| `max` in `pids.events` increased | PID limit breach | Kill the instance |
| A new PID in the cgroup | `process_created` observation; a deviation when `allow_spawn = false` and it is not the first process | `on_deviation` |
| Podman `exec` event | Someone ran a command inside the instance | `on_deviation` |

The kill is `podman kill --signal KILL`. The evidence records `latency_ms` from the decision to the kill. CPU is throttled by the kernel at the `cpus` limit and is not a breach.

## Evidence

All runtime events have class `runtime` and `policy_status` `not_evaluated`.

| Outcome | Origin | Reason code | Durable | Detail |
|---|---|---|---|---|
| `instance_launched` | E-15 | | yes | `alias`, `instance_id`, `container`, `launch_spec` (names, no values) |
| `process_created` | E-17 | | no | `alias`, `instance_id`, `pid`, `comm` |
| `deviation` | E-17 | `UNDECLARED_PROCESS`, `EXEC_INTO_INSTANCE` | yes | `action` (`alert` or `kill-instance`), `latency_ms` when killed |
| `limit_breach` | E-17 | `MEMORY_LIMIT`, `PIDS_LIMIT` | yes | `action` `kill-instance`, counters, limit, `latency_ms` |
| `instance_killed` | E-17 | `OPERATOR_KILL` | yes | `actor`, `reason` |
| `instance_exited` | E-15 | none (requested), `INSTANCE_EXITED_UNEXPECTEDLY`, `MEMORY_LIMIT` | yes | `expected`, `exit_code`, `oom_killed`, `memory_peak_bytes`, `cpu_usage_usec`, `pids_peak`, `kill_reason`, `stderr_bytes` |
| `monitor_degraded` | E-17 | `MONITOR_UNAVAILABLE` | no | The monitor could not find the instance's cgroup after 20 tries |
| `evidence_dropped` | E-15 | | yes | `events`: runtime events dropped because more than 1,024 were produced before the journal was attached |

Stderr content never enters evidence or harness traffic; only its size does. It is kept in a 1 MiB ring per instance (CP-37) and the control API returns its last 64 KiB.

## Commands

| Command | What it does |
|---|---|
| `smcpctl runtime doctor [--json] [--podman PATH] [--config FILE]` | Check the enforced-profile prerequisites (offline) |
| `smcpctl runtime spec [--config FILE]` | Print the launch specification of every server (offline) |
| `smcpctl runtime status [--config FILE]` | Launcher, defaults and instance counts by state |
| `smcpctl runtime instances [--config FILE]` | The instance table |
| `smcpctl runtime show <id> [--config FILE]` | One instance with its observations and stderr tail |
| `smcpctl runtime kill <id> [--reason TEXT] [--config FILE]` | Kill an instance now; recorded as `instance_killed` with your identity |

The control routes are documented in [api/runtime.md](api/runtime.md).

## Errors

| Message | Cause |
|---|---|
| `enforced-profile prerequisites missing: ...` | A doctor check failed at startup (see above) |
| `sandbox: podman not found on PATH; install rootless Podman or set runtime.podman` | No Podman binary |
| `mount refused: ...` | A mount grant broke a rule in "Mount grants" |
| `server artifact unavailable: <path> is not a regular file` | The server command does not exist (no image configured) |
| `environment variable X is reserved: it would configure Podman itself` | A reserved name in `env` or `secret_env` |
| `runtime.server "x" requests egress but no Egress Broker is enabled ([egress] enabled = true)` | `network = "egress"` without `[egress] enabled = true` |
| `runtime.server "x": egress for sandboxed servers is not available yet: ...` | `network = "egress"` with the broker enabled; see "Limits" |
| `runtime.server "x": scope "session" is not supported yet` | Only shared instances exist |
| `runtime.image must be referenced by digest` | An image without `@sha256:` (SR-3.6-1) |

Errors that Podman reports when it starts a container appear in the server's stderr and in the `launch:` or `connect` startup error. Common ones:

| Podman or crun error | Fix |
|---|---|
| `container uses ID mappings ... but doesn't map UID 1000` | `user` is not below `userns_size` |
| `not enough unused IDs in user namespace` | The user's subordinate range is too small for the number of instances times `userns_size` |
| `crun: chown ...: Invalid argument` | A mount target below a tmpfs path; choose another target |
| `cannot set memory limit` or missing controllers | Delegate the `memory`, `pids` and `cpu` controllers (see `cgroup-delegation`) |

## Limits of this implementation

- Sandboxed servers cannot use the Egress Broker (E-18) yet. The launcher implements `pipeline.EgressAware`, so the broker hands it its attacher instead of wrapping it, but creating a network namespace for a rootless container that reaches the broker's listeners and letting the broker install its nftables rules in it (which needs privileges in the container's user namespace) is not built. A server with `network = "egress"` is refused rather than started without a network or with an unconfined one.
- Instance scope is shared (one instance per server, started with the Gateway). Per-session and per-call instances (FR-5.10), reuse and idle teardown (FR-5.11), and restart or revision suspension after crashes (FR-5.12) need the registry to acquire instances per call; they are not built.
- Containment actions `suspend-revision` and `suspend-session` (FR-5.35) are not built; `alert` and `kill-instance` are.
- Declared behavior rules come from `[[runtime.server]]` (`allow_spawn`, `on_deviation`), not yet from signed manifests (E-13).
- File opens outside mounts and network connection attempts are prevented (read-only root, no network) but not observed: observing them needs eBPF or a seccomp notifier.
- Mount grants come from the operator's configuration; the intersection with manifest-declared and policy-granted roots (SR-4.6-1) needs manifests and policy roots.
- The Gateway and rootless Podman run as one identity, `smcp-core`; CP-46's separate `smcp-srv` identity is created with its range but not used yet.
- No AppArmor or SELinux profile is shipped; Podman applies its defaults where it can, and `apparmor_profile` and `selinux_type` select others.
