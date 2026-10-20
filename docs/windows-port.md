# Windows port: measured gaps and plan

For contributors. The owner decided on 2026-10-18 that the Gateway also runs on Windows (SRS FR-21, planned for v1.3.0; the requirements are in `srs_build/req7-windows.txt`, pull request #131). This page records where the code stood when the port started, what the first step changed, what each FR-21 area will cost, and the requirements that look infeasible or mis-specified as written.

No Windows installation mode is supported yet. A Windows build of `smcpd` starts with keys protected by DPAPI in a state directory with a protected DACL and launches backends in Job Objects, but refuses to open the UDS Harness Profile (see [What fails closed](#what-fails-closed-on-windows-today)).

## Measured gaps (2026-10-18, commit d9dde78)

Measured on macOS arm64 with Go 1.26.9, `GOOS=windows GOARCH=amd64`, `CGO_ENABLED=0`. `go build` stops at the first package that fails and skips its dependents, so the list was completed by fixing each failure and building again, and the tests were compiled per package with `go test -c -gcflags=-e`.

### Compile failures (`go build ./...`)

| Package | File | Cause | Fix in this step |
|---|---|---|---|
| `internal/tunnel` | `tunnel.go` | `syscall.SysProcAttr{Setpgid: true}` (process groups) | `detach_unix.go`; `detach_windows.go` uses `CREATE_NEW_PROCESS_GROUP` |
| `internal/sandbox/probe` | `probe.go` | `syscall.Getrusage`, `RUSAGE_SELF` | `cputime_unix.go`; `cputime_windows.go` uses `GetProcessTimes` |
| `internal/sandbox` | `delegate.go`, `secretacl.go` | `syscall.Stat_t` (file owner UID) | `owner_unix.go`; `owner_windows.go` reports no POSIX owner (never "owned by self") |
| `internal/library` | `library.go` | `syscall.Flock`, `LOCK_EX`, `LOCK_NB`, `LOCK_UN` | `flock_unix.go`; `flock_windows.go` uses `LockFileEx` with `LOCKFILE_FAIL_IMMEDIATELY` (same semantics) |

Nothing else failed: every other package, all eight commands and both `windows/amd64` and `windows/arm64` build once these four are split. `go vet` for Windows found nothing beyond the test files below.

### Test compile failures (`go vet ./...`, `go test -c`)

| Package | File | Cause | Fix in this step |
|---|---|---|---|
| `internal/edge` | `uds_test.go` | `syscall.Stat_t` (socket group) | `fileGID` in `fileowner_unix_test.go` and `fileowner_windows_test.go` |
| `internal/acceptance` | `at20_limits_test.go` | `syscall.Statfs` | `freeBytes` in `freebytes_unix_test.go`; Windows uses `GetDiskFreeSpaceEx` |
| `internal/sandbox` | `fake_test.go` | `syscall.Kill` (the fake Podman) | `killPID` and `pidAlive` in `fake_unix_test.go` and `fake_windows_test.go` |
| `internal/sandbox` | `rootfs_test.go` | `syscall.Umask` | the file is constrained to `unix` (it tests a Linux rootfs) |

### Areas checked that need no build change

- **os/user, setuid**: `os/user` compiles on Windows; `user.LookupGroup` is only used by the UDS listener, which is now refused on Windows. No `setuid` call exists outside Linux-constrained files. `os.Getuid` and `os.Geteuid` return -1 on Windows: the installer, `remote.go` and the sandbox compare them, so every such comparison has to be reviewed when its feature is ported.
- **nftables, AppArmor, seccomp, cgroups, POSIX ACLs**: already behind `linux` constraints with `!linux` stubs that refuse (`internal/egress`, `internal/posixacl`, `internal/sandbox`). The Podman sandbox's prerequisite doctor fails its essential `os` check off Linux, so `[runtime] sandbox = "podman"` refuses to start on Windows; Podman Desktop for Windows is never used as a confining launcher.
- **Seatbelt**: not used by the Gateway (macOS runs the Standalone profile).
- **Signals**: `syscall.SIGTERM`, `SIGKILL` and `SIGHUP` exist as constants on Windows, so the code compiles, but `Process.Signal(SIGTERM)` fails there (the backend shutdown sequence in `internal/pipeline` and stopping the tunnel in `internal/tunnel` under `smcpctl remote disable` fall through to their kill path or report the error), and `SIGHUP` is never delivered, so reload works only through `smcpctl` and the admin API. Go delivers `CTRL_C` as `os.Interrupt` and `CTRL_CLOSE`, `CTRL_LOGOFF` and `CTRL_SHUTDOWN` as `SIGTERM`, so the existing `signal.NotifyContext` in `smcpd` and the adapters already covers the console half of FR-21.7; the Service Control Manager half needs `golang.org/x/sys/windows/svc`.
- **File modes**: 239 mode literals (`0o600`, `0o700`, ...) in non-test code. They compile and are ignored by NTFS beyond the read-only bit. They are harmless as long as no check relies on them, which is why `keys.CheckPrivate` now fails closed on Windows (below).
- **cgo dependencies**: `github.com/duckdb/duckdb-go/v2` is the only cgo dependency. Its bindings ship a prebuilt static library for `windows-amd64` (built with MinGW-w64, linked with `-lstdc++ --static`), none for `windows-arm64`. A cgo Windows build would therefore need a MinGW toolchain and would cover amd64 only. With `CGO_ENABLED=0`, which is how every release binary is built, `internal/obsstore` uses its JSON Lines backend (`duckdb_nocgo.go`), as FR-21.18 states. The Neo4j driver (`neo4j-go-driver/v6`), `nftables` (Linux-only use), age, minisign and the MCP SDK are pure Go.

## What fails closed on Windows today

Each feature that is not ported refuses with an error naming the FR-21 requirement, instead of running with weaker protection:

| Where | Behavior on Windows | Until |
|---|---|---|
| `edge.ListenUDS` | refuses to listen, so no AF_UNIX socket is created | FR-21.8 named pipe and FR-21.9 SID mapping |
| `profile.Resolve` | `profile = "enforced"` fails; `auto` resolves to Standalone, label "not enforced", installation mode `windows-user` (the machine-mode service reports `windows-machine`). Inside WSL every mode, `enforced` included, resolves to Standalone with mode `wsl2` | permanent (SR-4-2) |
| `sandbox.FromConfig` (unchanged) | `[runtime] sandbox = "podman"` fails the essential `os` check | permanent |

On Linux and macOS behavior is unchanged: the new `_unix.go` and `!windows` files contain the code that was there before.

## Backend launch and Job Objects (FR-21.11, FR-21.12)

Since 2026-10-19 `pipeline.SubprocessLauncher` starts backends on Windows through `internal/winsandbox`, so the launch gate above is lifted:

- The process is created with `CreateProcess` from the absolute executable path, with the argument vector joined by the Microsoft C runtime quoting rules (`windows.ComposeCommandLine`). No shell is involved, so `&`, `|` and `%PATH%` reach the backend unchanged.
- The process is a member of its own Job Object from creation: the job is passed in `PROC_THREAD_ATTRIBUTE_JOB_LIST`, and no `AssignProcessToJobObject` call is made. The child inherits only its three standard stream handles (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).
- The Job Object has kill-on-close, a per-process and a whole-job memory limit, an active-process limit and a hard CPU rate cap, all from `[[runtime.server]]`, then the manifest's `capabilities.resources`, then `[runtime]` (CP-24 by default: 512 MiB, 1 CPU, 128 processes). Breakaway is not allowed, and the user-interface restrictions (desktop, clipboard, global atoms, system parameters) are set. The backend is a console program started without a window, so Windows adds a console host (`conhost.exe`) to the job; measured on `windows-latest`, it is listed in the job but not counted against the process limit.
- When the job reports a broken memory or process limit, the whole instance is terminated and a line naming the limit is added to its diagnostic output, as a cgroup limit ends the instance in the Enforced profile.
- `Close` closes standard input, waits, and then terminates the Job Object (Windows has no SIGTERM for a backend). Closing the job also ends any process the backend left behind; if `smcpd` itself ends, however it ends, the kernel closes the job handle and kill-on-close ends every backend process.
- `cmd.exe`, `powershell.exe`, `pwsh.exe` and `.bat` or `.cmd` files are refused at enablement (reason `SHELL_LAUNCH`) and again at launch (SR-4.8-2). The check reads Windows path rules on every platform: case is ignored, trailing dots and spaces are stripped, and alternate data streams are refused. A renamed copy of an interpreter is not recognized by name.

These run in the per-user mode too; they give the macOS Standalone posture plus resource limits, not confinement, and the label stays "not enforced" (SR-4-2).

### Ported since the first step

| Where | Behavior on Windows | Requirement |
|---|---|---|
| `keys.CheckPrivate` (called by `app.Start`) | Reads no file mode. Refuses to start with `state_acl` when the state directory's DACL is not protected or grants an account other than the one running `smcpd`, SYSTEM and Administrators, or when a private file grants one; refuses with `key_protection` when a private file is not a DPAPI blob this account can decrypt. The file is left as it is. | FR-21.5, FR-21.10 |
| `keys.Ensure` (`smcpctl bootstrap`, `smcpctl install`) | Gives the state directory a protected DACL (inheritance disabled; full control for the current account, SYSTEM and Administrators) and writes the CA, listener, evidence and pending keys and the operator token as DPAPI blobs (`CryptProtectData`, user scope). The policy-signing key of `internal/policystore` is a DPAPI blob too. | FR-21.5, FR-21.10 |
| `internal/durable` (Policy Store, `keys.WriteFileAtomic` and its users: backup restore, principals, observation objects, the package index) | A flushed file is renamed with `MoveFileEx` and `MOVEFILE_REPLACE_EXISTING` and `MOVEFILE_WRITE_THROUGH`; a new immutable revision with `MoveFileEx` without replace (it refuses an existing name); no directory is opened. Linux and macOS keep rename and directory `fsync`. | FR-21.23 |
| `health.FreeBytes` | `GetDiskFreeSpaceEx`, so the `audit_capacity` and `disk_low` checks fire on Windows. | FR-21.26 |
| `smcpctl install` (per-user mode) | Refuses a Windows build below 22631 (Windows 11 23H2) or, on Windows Server, below 20348 (Server 2022), naming both. Creates `%LOCALAPPDATA%\smcp-gateway\` with `config\`, `state\`, `log\` and `exports\`, each with a protected DACL (this user, SYSTEM, Administrators); bootstraps the keys (DPAPI), configuration and policy; registers the Task Scheduler task `smcp-gateway` with `schtasks /create /xml` (a logon trigger for this user's SID, least privilege, no time limit), or, when Windows refuses it, the `HKCU\...\Run` value `smcp-gateway` with a notice; starts `smcpd -supervise` and waits for health. The definition file (`config\smcpd-task.xml` or `config\smcpd-run.txt`) is what `uninstall` and `upgrade` find. | FR-21.1, FR-21.5, FR-21.6 |
| `smcpd -supervise` (`internal/winsvc`) | Runs `smcpd` as a child in a kill-on-close Job Object and starts it again after a non-zero exit (1 s doubling to 60 s). Task Scheduler's own restart setting covers only a task that fails to start, so the supervisor is what restarts a crashed Gateway. | FR-21.6 |
| Stop of a per-user `smcpd` | `smcpd` and its supervisor wait on a session-local named event derived from the configuration path; `smcpctl uninstall` sets it, which is the orderly stop (journal stop record, backends stopped). `CTRL_C` and `CTRL_BREAK` are the same orderly stop. `CTRL_CLOSE`, `CTRL_LOGOFF` and `CTRL_SHUTDOWN` record the stop in the journal first (`app.RecordStop`) and exit within 3.5 seconds. | FR-21.7 |
| `smcpd` under the Service Control Manager | Stop, shutdown and preshutdown requests cancel the Gateway's context (the orderly stop), with a 60-second wait hint; a failure exits with a non-zero service exit code so that recovery actions apply. The machine-mode installation that registers the service is not built yet. | FR-21.6, FR-21.7 |
| `smcpctl doctor` | Reports the installation mode and label, and runs the state-directory DACL and key-protection check. | FR-21.5, FR-21.10, SR-4-2 |
| Secret files read by `smcpctl` (`--admin-password-file` and the like) | No mode check; the file's DACL may grant only this account, SYSTEM and Administrators (`winsec.CheckOwnerOnly`). | FR-21.2 |

## Boundary between the platform runtime and the Windows sandbox

Two streams of work port the Gateway to Windows. The platform runtime (`internal/winsec`, `internal/durable`, the named-pipe transport in `internal/edge`, the service, `smcpctl install`, `install.ps1`, the archives and the MSI) and the Windows sandbox (backend launch and Job Objects, FR-21.11, FR-21.12, SR-4.8-2; AppContainer profiles and their grants, FR-21.13, SR-4.1-3, SR-4.6-2; WFP egress, FR-21.14, SR-4.5-3; the bundled ContextForge Job Object). They meet at these points, and neither changes the other's files:

- `internal/winsec` is the shared primitive layer. The sandbox uses `ProcessUserSID`, `LookupSID`, `Grant` and `Revoke` (an allow entry for an AppContainer SID on a package tree, scratch directory or slot, inherited below a directory) and `SecurityAttributes` (a protected descriptor for an object it creates), and may add its own files to the package (`appcontainer_windows.go`, `job_windows.go`) without changing the existing functions' behavior.
- Backend launch belongs to the sandbox (`internal/winsandbox`, used by `pipeline.SubprocessLauncher` on Windows; see above). The platform runtime never starts a backend.
- The installation mode (`windows-user`, `windows-machine`) is decided by the platform runtime (the service and `smcpctl install`) and read by the sandbox to choose AppContainer containment in the machine mode.
- A state directory and its keys are the platform runtime's; the sandbox never grants an AppContainer SID access to them.

## AppContainer and egress filters, machine mode (FR-21.13, FR-21.14)

With `[runtime] sandbox = "appcontainer"` each packaged server revision gets a placement when it is enabled, recorded in `<state>/appcontainer/<profile>.json` (`internal/winsandbox.Placements`, called by the package library):

- An AppContainer profile with no capabilities, named `smcp-` and the first 40 hexadecimal digits of the SHA-256 of `serverID@revision`, so the profile and its SID are the same at enable, at every start and at disable (one profile per enabled revision, finding 2).
- Access entries for that SID, written once at enablement and inherited below (finding 3): read and execute on the unpacked package tree, modify on the scratch directory of the configured alias (`<state>/packages/work/<alias>`, also the instance's `TEMP`), and read and execute or modify on each manifest slot that the configuration binds to a path. A changed grant is applied by enabling again; entries of paths no longer granted are removed.
- WFP filters in the Gateway's own persistent provider and sublayer: a hard block (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`) of the SID at the ALE connect and receive/accept layers for IPv4 and IPv6, and a higher-weight permit for TCP to `127.0.0.1` on the revision's broker port. The loopback exemption (`NetworkIsolationSetAppContainerConfig`) is added for the SID; it opens every loopback port, so the block filter is what limits it to the broker port.
- The broker port is a loopback port chosen at enablement. At each start the Egress Broker binds the instance's proxy on that port and binds no destination endpoints (the instance reaches granted destinations through the proxy; S1 header injection through an endpoint is therefore not offered to a contained instance).

At start the library refuses a revision without a placement, or whose placement names another scratch directory, with `CONTAINMENT_FAILED`, and the Windows launcher starts the backend with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` for the profile, inside its Job Object. Disabling, retiring or revoking the revision removes the filters, the exemption, every access entry of the SID on the recorded paths, the profile and the record; a suspended revision keeps them. `Placements.RemoveAll` is the uninstall step (SR-4.5-3).

What needs an administrator, as measured on the `windows-latest` runner: creating and deleting the profile and writing access entries need only rights on the paths; opening the filter engine, adding the filters and changing the loopback exemption need an administrator. So the enable and disable steps run elevated (`smcpctl package enable` from an elevated prompt), and the service account never changes filters. CreateProcess for an AppContainer fails with `ERROR_ENVVAR_NOT_FOUND` when `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `TEMP` or `TMP` is missing from the environment block, so the launcher adds them from the Gateway's environment; Windows rewrites them to the container's folders.

The health cause is `partially_confined` instead of `unconfined` while the installation mode is `windows-machine` and every configured server runs in an AppContainer; one uncontained server (a `command` server) brings back `unconfined`. The label stays "not enforced".

The bundled ContextForge instance is not placed in an AppContainer: on Windows it runs as a managed process in its own Job Object (`winsandbox.StartManaged`, kill-on-close, CP-24 limits), and `winsandbox.ContextForgeUnconfinedCheck` reports `contextforge_unconfined` while it runs.

## Continuous integration

The job `windows` in `.github/workflows/ci.yml` runs on `windows-latest` for every pull request that changes more than documentation (the `changes` gate of [ci.md](ci.md)). It is not a required check. It builds every package for `windows/amd64` and `windows/arm64` with `CGO_ENABLED=0`, runs `go vet`, runs the unit tests of the packages in `WINDOWS_TEST_PACKAGES` (the job fails if one fails), and then runs every package once more without failing the job, writing the per-package result to the step summary as the measure of the port. The package list and the reason each other package is excluded are in the workflow. It also runs the `TestWindows*` tests of `internal/keys`, `internal/pipeline` and `internal/edge`, which check the fail-closed gates above, and the Windows sandbox tests (`internal/winsandbox`, the Windows launch tests of `internal/pipeline` and `internal/library`, and the HF-20 and HF-21 fixtures of `internal/hostile` against the Job Object launcher), whose requirement claims the `status` job merges from `build/windows-sandbox-test.json`.

### First Windows test run (windows-latest, 2026-10-19)

`go test -short ./...` with `CGO_ENABLED=0` on `windows-latest` took about 90 seconds. 24 packages pass, 40 fail and 13 have no tests. The failures group into a small number of causes, most of which are tests written for POSIX rather than product defects; the product gaps among them are marked.

| Cause | Packages | Kind |
|---|---|---|
| `smcpd` start refused by the `CheckPrivate` gate | `internal/app`, `internal/e2e`, `internal/remote`, `internal/conformance`, `internal/adapter`, parts of `cmd/smcpctl` | intended (fail closed) |
| Server launch refused by the launch gate | `internal/packaging` (probe) | intended (fail closed) |
| Test fixtures use POSIX commands such as `/inproc/t` or `/fake/mem`, which `filepath.IsAbs` rejects on Windows | `internal/backend`, `internal/edge`, `internal/filters`, `internal/pipeline`, `internal/sandbox` | tests |
| POSIX mode checks: the tests expect `0600`, and the product refuses some files on Windows (the vault's "readable by their owner only" check, the graph password file check) | `internal/keys`, `internal/secrets`, `internal/graph`, `internal/obsstore`, `internal/baseline`, `internal/principals`, `internal/diag`, `internal/obspolicy`, `internal/research`, `internal/approval`, `internal/harness`, `scripts/agents` | product (fails closed today; FR-21.5 replaces it with a DACL check) and tests |
| Directory `fsync` fails with "Access is denied" | `internal/policystore`, `internal/policyadmin`, `internal/backup` | product: the Policy Store cannot publish on Windows until directory sync is skipped there (NTFS metadata is journaled; `FlushFileBuffers` needs a file handle) |
| Windows paths written by the tests into TOML basic strings (`\U` read as an escape) | `internal/adminapi`, `internal/consoleauth`, `internal/filterapi`, `internal/openapi`, `tools/openapi` | tests; also a documentation point: Windows paths in `smcp.toml` need literal strings (`'C:\...'`) or forward slashes |
| POSIX default paths (`/usr/bin/podman`, `sudo`) checked as absolute | `internal/config`, `internal/packaging` | product defaults, Linux-only features |
| Request-filter path canonicalization is POSIX: `/etc/passwd` resolves under the working directory as `C:\...\etc\passwd` | `internal/filters`, `internal/policy` | product, security-relevant: path rules need the FR-21.25 Windows semantics before any Windows mode is supported |
| Free disk space not measured off Linux and macOS | `internal/health` | product: `GetDiskFreeSpaceEx` for the CP quota check |
| Test binaries built without `.exe` | `cmd/smcpd`, `cmd/smcp-refserver`, `cmd/smcpctl`, `internal/packaging` | tests |
| Tools absent on Windows (`sh`, `nft`, `node`) | `tools/installsh`, `internal/tunnel`, `internal/adapter` | tests (FR-21.4 replaces `install.sh` with `install.ps1`) |
| Latency bound on a shared runner | `internal/perf` | tests |

Passing on Windows: `cmd/smcp-hostile`, `docs`, `internal/acceptance` (its Linux scenarios skip), `internal/analytics`, `internal/anomaly`, `internal/audit`, `internal/authguard`, `internal/consoleapi`, `internal/egress`, `internal/hostile`, `internal/library` (including the `LockFileEx` registry lock), `internal/metrics`, `internal/observe`, `internal/posixacl`, `internal/profile`, `internal/reqtest`, `internal/sandbox/probe`, `internal/session`, `internal/testport`, `internal/versions`, `packaging/linux`, `tools/provenance`, `tools/reqreport`, `tools/sbomcheck`.

## Effort by FR-21 area

Estimates are engineer-days for one developer who knows the code base, including tests on a Windows runner. They assume the per-user mode first.

| Area | Requirements | Estimate | Notes |
|---|---|---|---|
| Build portability, CI | FR-21.2, FR-21.19 | 1 (done here) + 2 to 3 | `windows-11-arm` job, test triage, build constraints for Linux-only tests |
| ACLs | FR-21.5, FR-21.16, the `CheckPrivate` gate | 3 to 5 | `GetNamedSecurityInfo` and `SetNamedSecurityInfo` with a protected DACL; the check replaces the mode check and lifts the start gate |
| DPAPI keys | FR-21.10, SR-2.13-4 | 3 to 4 | `CryptProtectData` wrapper in `internal/keys`; see the DPAPI-NG finding below |
| Backend launch and Job Objects | FR-21.11, FR-21.12, SR-4.8-2 | 6 to 8 | `os/exec` cannot do it (below): an own `CreateProcess` path with `STARTUPINFOEX`, `PROC_THREAD_ATTRIBUTE_JOB_LIST`, pipes and the shutdown sequence; lifts the launch gate |
| Service and stop | FR-21.6, FR-21.7 | 4 to 6 | Task Scheduler XML for per-user, `x/sys/windows/svc/mgr` for the machine mode, SCM stop and preshutdown |
| install.ps1, archives, Defender | FR-21.3, FR-21.4, FR-21.22, FR-21.24 | 4 to 6 | goreleaser zip targets; minisign verification through OpenSSL needs a key conversion and the prehashed (BLAKE2b) form |
| Named pipes | FR-21.8, FR-21.9, SR-2.8-6 | 5 to 7 | own pipe server on `x/sys/windows` or `github.com/Microsoft/go-winio`; conformance fixtures over the pipe |
| Path rules | FR-21.25 | 2 to 3 | `GetFinalPathNameByHandle`, stream, device-name and prefix checks |
| Clients and real agents | FR-21.17, FR-21.21 | 3 to 5 | matrix paths, adapter CRLF handling, the agents workflow on Windows |
| Acceptance subset | FR-21.20 | 3 to 5 | needs launch and the service; per-mode results in the status data |
| AppContainer | FR-21.13, SR-4.1-3, SR-4.6-2 | 10 to 15, high risk | per-revision AppContainer profiles and ACEs written at enablement (finding 2 and 3, applied); spike first |
| Egress (WFP) | FR-21.14, SR-4.5-3 | 10 to 15, high risk | no WFP wrapper in `x/sys/windows`; `inet.af/wf` (BSD, from Tailscale) is the candidate; runtime rights problem below |
| WSL2 mode | FR-21.15 | 4 to 6 + a recorded host | hosted runners have no nested virtualization |

Total: roughly 60 to 90 engineer-days, of which the machine mode (AppContainer, WFP, SCM service, virtual account) is about half.

## Recommended order

1. This step: build, `go vet`, fail-closed gates, non-required CI job.
2. Test portability (fixture paths through `filepath`, `.exe` suffixes, TOML literal strings, mode checks behind a helper) and the small product fixes the first run found: directory `fsync`, free disk space, POSIX defaults. Each package that passes moves into `WINDOWS_TEST_PACKAGES`.
3. ACL checks and DPAPI key protection, which lift the `CheckPrivate` gate so `smcpd` starts in the per-user mode with nothing to launch.
4. Windows path rules (FR-21.25) for the request filters and filesystem slots, before any backend can run.
5. Backend launch with Job Objects and the interpreter refusal, which lifts the launch gate and gives the per-user mode parity with macOS Standalone.
6. Stop handling and the Task Scheduler task; `smcpctl install` on Windows.
7. Release zips, `install.ps1`, the Defender scan and the unsigned-binary notices.
8. Adapters, client paths and the real-agent suite; the acceptance subset in the per-user mode; make the `windows` job required and add `windows-11-arm`.
9. Named pipes and SID mapping.
10. Machine mode, after a spike that answers the AppContainer and WFP questions below: SCM service and virtual account, AppContainer, WFP egress.
11. WSL2 mode.

## Risks and what Windows can honestly claim

- **Sandbox strength.** The Linux Enforced sandbox gives each instance its own user namespace, mount namespace with a pinned image, seccomp filter, LSM profile, cgroup and network namespace behind nftables. An AppContainer gives a separate SID, a capability-less token and default-deny on most of the user's objects, but no system-call filter, read access to everything granted to ALL APPLICATION PACKAGES (most of `C:\Windows` and `C:\Program Files`), the host's interpreter rather than a pinned image, and a shared kernel attack surface with a much larger Win32k and driver surface. Job Objects cover memory, CPU and process count but not disk I/O fairly. #131's position is right: every Windows mode claims the Standalone profile and the label "not enforced", the machine mode may report `partially_confined` instead of `unconfined`, and no Windows result may count toward the Enforced label.
- **Per-user mode is macOS parity, no more.** Agents and `smcpd` run as the same account, so an agent can read the Gateway's state whatever the DACL says. DPAPI under that account protects against copying the state to another host or account, not against the agent. The docs should say so.
- **WSL2 mode.** Any process of the Windows user can run `wsl.exe -u root`, and root in the distribution can re-enable interop by editing `wsl.conf`. "Not enforced" is the honest label.
- **Unsigned binaries.** Smart App Control blocks unsigned executables outright, and Defender flags unsigned Go binaries regularly; until Authenticode signing (FR-20.30) is funded some users cannot run the Gateway at all.

## Requirements in #131 to adjust before it merges

Applied on 2026-10-19 in #131 before it merged: each finding below changed the FR-21 record named (1: SR-2.13-4; 2: FR-21.13, FR-21.14, SR-4.1-3, SR-4.5-3, one AppContainer profile per enabled server revision created by the elevated enable step, the mechanism to be confirmed by the machine-mode spike; 3: SR-4.6-2; 4 and 12: FR-21.2; 5: FR-21.4 and FR-21.22; 6: FR-21.6; 7: FR-21.7; 8: FR-21.9; 9: FR-21.11 and SR-4.8-2; 10: SR-4-2; 11: FR-21.19; 13: new FR-21.23, Windows write durability). The request-filter path finding extended FR-21.25 to the Request Inspection Pipeline, the free-space finding added FR-21.26, Authenticode signing moved to FR-20.30, and the named-pipe SR is SR-2.8-6.

1. **SR-2.13-4 (DPAPI-NG to a SID) does not work on a workgroup host.** DPAPI-NG `SID=` protection descriptors depend on the Active Directory Group Key Distribution Service; on a stand-alone Windows 11 machine or a GitHub runner they fail. Use classic DPAPI (`CryptProtectData`) under the account that runs `smcpd`, as FR-21.10 does, or the DPAPI-NG `LOCAL=user` descriptor, and drop "on another host" from the verification unless the host is domain-joined.
2. **FR-21.14 and SR-4.1-3 conflict on who creates the loopback exemption and the WFP filters.** SR-4.1-3 derives an AppContainer SID per instance at run time, but `NetworkIsolationSetAppContainerConfig` (the loopback exemption) needs an administrator, and adding WFP filters needs rights the virtual service account does not have by default; FR-21.14 has `smcpctl install --machine` create them, before any instance SID exists. Also, a loopback exemption cannot be limited to one port (the rationale says it can); only the WFP filter limits the port. Options: one AppContainer per package created at enable time by an elevated step; or install grants `NT SERVICE\smcpd` the right to add filters in the Gateway's own WFP sublayer and the exemption is replaced by a WFP hard permit; or the broker is reached over a named pipe the AppContainer SID is granted (no loopback at all, but backends then need a pipe-aware proxy shim). This needs a spike before the requirement is fixed.
3. **SR-4.6-2 per-start ACEs on large trees.** Adding and removing ACEs naming a fresh SID on every start walks the whole tree for an interpreter or a `node_modules` directory (tens of thousands of files) and leaves stale ACEs after a crash. A per-package custom capability SID granted once at enable time, with the per-instance AppContainer SID used only for the scratch directory, gives the same isolation without the walk.
4. **FR-21.2 "POSIX modes confined to files with a non-Windows build constraint" is not achievable as worded.** Every `os.WriteFile`, `os.MkdirAll` and `os.OpenFile` takes a mode (239 literals today). The intent is that no protection on Windows relies on a mode; state it that way (for example: "no security check reads a POSIX mode or owner on Windows").
5. **FR-21.4 rationale: "Windows has no `curl | sh` path".** `irm <url> | iex` is the established equivalent (Scoop, Bun, uv use it). More important for the installer: the default execution policy (Restricted on Windows 11 clients, RemoteSigned on Server) refuses an unsigned, browser-downloaded `install.ps1`, so FR-21.22's verification "run `install.ps1` from a browser-downloaded copy" fails before the script runs unless the documented invocation is `irm | iex` or `-ExecutionPolicy Bypass`. Specify the supported invocation. Verifying a minisign signature with OpenSSL also needs the public key wrapped as an Ed25519 SubjectPublicKeyInfo and, for the default prehashed signatures, a BLAKE2b-512 digest of the file first; feasible, but worth stating that both the signature and the trusted-comment signature are checked.
6. **FR-21.6 per-user Task Scheduler logon trigger.** `schtasks /create /sc onlogon` refuses a standard user; a task registered through the Task Scheduler API with a `LogonTrigger` restricted to the user's own SID may be accepted. This needs a test on a non-administrator account before the requirement fixes Task Scheduler; the fallback without elevation is the `HKCU\...\Run` key, which has no restart-on-failure.
7. **FR-21.7 `CTRL_CLOSE` time budget.** Windows terminates a console process about 5 seconds after `CTRL_CLOSE`, `CTRL_LOGOFF` or `CTRL_SHUTDOWN`, whatever the handler does. If the CP-47 health-wait bound is longer, the statement cannot be met for those events; the Job Object's kill-on-close still ends every backend, but the journal stop record may be lost. Bound the requirement by the shorter of the two. The statement also lists `smcpctl stop` as an orderly process stop, but `smcpctl stop` is the emergency stop (every tool call refused until resumed; the Gateway keeps running); name the command meant, or drop it.
8. **FR-21.9 peer lookup in the machine mode.** A virtual service account cannot open another user's process token (`GetNamedPipeClientProcessId` then `OpenProcess` fails on the default process DACL), and a PID can be reused between the two calls. Specify pipe impersonation at identification level (`ImpersonateNamedPipeClient`, then `OpenThreadToken`) for the machine mode.
9. **FR-21.11 suspended creation through Go.** `os/exec` closes the primary thread handle, so a suspended child cannot be resumed without enumerating its threads. Specify the outcome (the process is in the Job Object before it runs) and let the implementation use `PROC_THREAD_ATTRIBUTE_JOB_LIST`, which places the process in the job at creation without suspension. Also, refusing `cmd.exe` by name does not stop a backend from starting a shell itself (Node's `child_process` with `shell: true`, a renamed copy); SR-4.8-2 is a rule for the Server Runtime Manager only and the docs should say so.
10. **SR-4-2 WSL detection.** `WSL_DISTRO_NAME` is set only for processes started through `wsl.exe`, not for a systemd service inside the distribution. Detect from `/proc/sys/kernel/osrelease` (contains `microsoft` or `WSL`) and treat the variable as a second signal only.
11. **FR-21.19 "excluded by build constraints".** Many Linux-only tests skip at run time (`t.Skip` on `runtime.GOOS` or a missing tool), which is equivalent for CI. Allow either.
12. **FR-21.2 source and rationale.** The build fails in four packages, not three: `internal/sandbox/probe` (`syscall.Getrusage`) as well, and `go vet` fails in three more test packages. The command list also omits `smcp-hostile` and `smcp-workload`, which are built by `go build ./...` and now build too.
13. **Missing record: Policy Store durability on Windows.** The Policy Store, its activation and backup restore sync directories after renames, which Windows refuses. A requirement (or a note under FR-21.2) should state the Windows durability rule so it is tested, not just patched.
