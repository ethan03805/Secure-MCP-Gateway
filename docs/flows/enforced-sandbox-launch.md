# Enforced sandbox launch

How `smcpd` starts one backend server in a rootless Podman container when `[runtime] sandbox = "podman"` (FR-5.27, FR-13.9, SR-3-2, SR-4-1, SR-4.5-1 to SR-4.7-2, SR-2.14-1; ARCH §18.1). The operator procedure and every option are in the [server sandbox guide](../sandbox.md).

```mermaid
sequenceDiagram
  autonumber
  participant D as smcpd start-up
  participant DR as sandbox.Doctor
  participant E15 as E-15 Runtime Manager (sandbox.Launcher)
  participant E10 as E-10 Server registry (backend.Start)
  participant E20 as E-20 Secret Broker
  participant E13 as E-13 Library re-verification
  participant P as Podman (rootless, crun)
  participant S as Server instance (E-16 container)
  participant E17 as E-17 Runtime Monitor
  participant E21 as E-21 Journal

  D->>DR: prerequisite checks (kernel, rootless, cgroup v2, user namespaces, subids, Podman, crun, delegation, seccomp, nftables, systemd, LSM)
  DR-->>D: failed checks
  Note over D,DR: mode enforced refuses start-up on any failed check. mode auto refuses only on the checks the container needs and resolves to standalone otherwise
  D->>E15: Start
  E15->>P: podman ps, rm --force each smcp.managed container of an earlier Gateway
  E15->>P: podman events (monitor stream)
  D->>D: profile.Resolve with the launcher (confined)
  D->>E10: start each configured server
  E10->>E10: refuse a high-risk server when the launcher is not confined (SR-4-1), check the launch spec is pinned
  E10->>E20: resolve secret_env and launch-time bindings (S1, S3, S4)
  E20->>E21: secret_use delivered or denied
  E20-->>E10: environment values, S3 file paths
  E10->>E10: instance environment from the allowlist plus configured and secret variables (SR-2.14-1)
  E10->>E13: Launch (packaged server)
  E13->>E13: artifact SHA-256 and unpacked tree digest against the import record (SR-3-2)
  E13->>E15: Launch
  E15->>E15: refuse network = egress (not available for sandboxed servers yet)
  E15->>E15: Build launch spec: limits, read-only root, cap-drop all, no-new-privileges, user namespace, network none, artifact digest, granted mounts, reserved variable check
  E15->>P: podman run --interactive with an argument vector, values passed in the Podman process environment
  P->>S: create and start the container
  E15->>E17: locate the cgroup before the first MCP message
  E15->>E21: instance_launched with the launch spec (names, no values), committed
  E15->>E17: watch the instance (cgroup files, inotify, events)
  E10->>S: MCP initialize, tools/list over stdin and stdout
  S-->>E10: tools
  E10->>E13: compare with the signed manifest
  Note over E10,E13: a changed tool list suspends the revision and the instance is not started
  E17->>E21: process_created, deviation, limit_breach, instance_exited
```

## Implementation

`internal/sandbox` (`FromConfig`, `Launcher`, `Build`, `PodmanArgs`, `Monitor`), wired in `cmd/smcpd/main.go`. The launcher chain from outside in is the library's verifying launcher (`internal/library/runtime.go`), the Secret Broker's wrapper (`internal/secrets/launcher.go`, which withdraws an instance's deliveries when it closes or fails to start) and `sandbox.Launcher`. The Egress Broker hands its attacher to the sandbox launcher (`SetEgress`) instead of wrapping it. Differences from the specification:

- `network = "egress"` is refused for sandboxed servers (`ErrEgressUnsupported`); a sandboxed server has no network at all.
- Instances are shared across sessions; per-session and per-call scopes (FR-5.10), idle teardown (FR-5.11) and restart with crash-loop suspension (FR-5.12) are not implemented. An instance that exits is not restarted.
- When the artifact check in step 14 fails, the revision is suspended and the server is skipped, but the launch-time secret deliveries of step 9 are not withdrawn until the Gateway stops or the alias is launched again, because the verifying launcher sits outside the Secret Broker's wrapper.
- AppArmor and SELinux profiles are passed to Podman only when configured; none ship. The `smcp-srv` service identity is not used.
- `scripts/ci-integration.sh` runs a second instance with `[runtime] sandbox = "podman"` on the linux-integration CI job, where a probe server must fail to open network sockets; the Linux-only tests in `internal/sandbox/integration_linux_test.go` exercise the launcher against Podman. macOS never reaches this flow and always runs the standalone profile.
