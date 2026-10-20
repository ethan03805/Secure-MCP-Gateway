# Verification gap list

Every requirement of the current requirement set that is not yet verified, grouped by primary element (the first E-xx of the requirement's allocation), with what is missing, followed by every requirement planned for v1.3.0 that is not yet verified ([Planned for v1.3.0](#planned-for-v130)). Checked on 2026-10-20 by the phase-11 steward pass against the CI status data of main `fe82231` (run https://github.com/ethan03805/Secure-MCP-Gateway/actions/runs/39412846028): 530 requirements, 491 verified, 38 partly verified, 1 unverified (FR-18.3), 0 failing, the same open set as at the v1.2.0 release; 147 more are planned for later releases and counted apart (146 for v1.3.0, one for v1.4.0). The current-set lines were written by the phase-10 steward pass from main `383485d` and still apply. `make status` produces the same report locally (`build/reqreport.md`); regenerate it before acting on an entry, because later merges change the counts.

Each entry is marked:

- **missing**: the behavior, or a stated part of it, does not exist in the code.
- **unverified**: the behavior appears to exist, but no test or record proves the whole statement yet. These need a test or an inspection record, not new code.
- **external**: the requirement needs an artifact or run outside the source tree (a release tag, a person, credentials, a third-party service). The entries that only the owner can unblock are collected in [Blocked on the owner](#blocked-on-the-owner) at the end.

Parent requirements whose verification is "Review the verification results of every child requirement" are verified by `tools/reqreport` once all their children are, and reported partial while some but not all children are verified. They are not listed below. In this status data they are: FR-8, FR-9, FR-10, FR-12, FR-13, FR-14, FR-15, FR-16, FR-18. FR-11 is not a roll-up: it is reviewed by Analysis against a performance report on the recorded reference hardware ([reference-hardware.md](../reference-hardware.md)), and its record is [FR-11.md](FR-11.md) (run 39203581561 of main `383485d`, every FR-11 child verified).

Requirements deferred from release 1.x (SRS Section 2.7, Appendix N) are not listed. Requirements planned for a later release with a `TARGET:` line (SRS Section 2.8) are not part of the current requirement set; those planned for v1.3.0 are listed in their own section, and FR-22.45 (planned for v1.4.0) is not listed.

The claiming tests of each partly verified requirement say, in the comment next to `reqtest.Partial`, which clauses are missing; `build/reqreport.md` lists the claiming tests. Some requirements are full claims only from the published result of a workflow run on a release tag, and partial claims from a run on any other ref (FR-13.3, FR-14.9, FR-15.2, FR-15.8; [verification/README.md](README.md#results-of-separate-workflows)). FR-13.3 and FR-14.9 are verified by the v1.1.0 runs; FR-15.2 needs the lockdown job, and FR-15.8 the matrix job, on the next release tag, v1.2.0.

## E-01 Harness Interface Endpoint

- FR-12.2 **unverified** (partly verified): The offline job does not run AT-07, AT-08 and AT-10.
- FR-16.1 **external** (partly verified): The Remote Access listener is tested behind a local tunnel stand-in.
- FR-16.2 **external** (partly verified): The tunnel drivers are tested against fake tailscale and cloudflared binaries.

## E-13 Library Trust Verifier

- FR-14.3 **unverified** (partly verified): The reference servers are packaged with the unconfined probe; the Podman probe is tested with the hostile packaging fixture only.

## E-21 Audit & Evidence Service

- FR-16.8 **external** (partly verified): The fields are tested on the listener; calls through a real tunnel are not.
- SR-6.1-1 **unverified** (partly verified): No single test triggers every event class under the most minimal policy.
- SR-6.7-1 **unverified** (partly verified): The AT-13 run checks credential formats, not a secret delivered by the Secret Broker on every captured surface.

## E-24 Management Console & Control API

- FR-8.24 **external** (partly verified): A scripted first-time task, not the Demonstration with three first-time users.
- FR-8.30 **external** (partly verified): The CI job `console-previous-browsers` runs the suite on the builds of Playwright 1.63.0 (Chromium 153, Firefox 155, WebKit 26.6); the previous major release of each browser product (no Playwright release has Chromium 155 or Firefox 156) and Safari itself are not run.
- FR-8.32 **unverified** (partly verified): axe (full WCAG 2.2 AA tag set) runs on every view as it loads and on the keyboard specs' intermediate states, not on every state of the other specs.
- FR-8.33 **unverified** (partly verified): The Runtime instance kill on a real instance runs in Chromium only (CI job `console-enforced`), and no claim aggregates the per-test results into a full claim.
- FR-12.7 **unverified** (partly verified): 20 of the 23 subcommands run on one installation in each profile (TestAdminCLIDemonstration); install --profile enforced and upgrade on a real Enforced installation, and a Demonstration record of a release build, are missing.
- FR-13.7 **unverified** (partly verified): The launchd and systemd service paths of each profile are not exercised.
- FR-18.1 **unverified** (partly verified): The install guide has not been followed on clean hosts.

## E-25 Graph Database Engine

- FR-9.1 **missing** (partly verified): Relationship types owned by other elements are not created by the mirror.
- SR-7.4-1 **unverified** (partly verified): The engine itself is not run as smcp-data on an Enforced host with its configuration and firewall rules inspected together.

## E-28 Data Lifecycle & Memory Manager

- FR-9.10 **missing** (partly verified): The page-cache measurement and the other budgeted components are not covered.
- FR-9.11 **missing** (partly verified): The page-cache measurement and the other budgeted components are not covered.

## E-29 Observation Collector

- FR-10.1 **unverified** (partly verified): The collector's offer path is tested with consumption stalled; instrumented elements processing calls during the stall are not.
- FR-10.2 **missing** (partly verified): Only the edge's stages emit spans; a call without an approval has no approval span.
- FR-10.5 **unverified** (partly verified): The fixture covers the argument features only.
- FR-10.10 **unverified** (partly verified): P-213 is computed from journal timestamps; no independent harness-side measurement is compared.

## E-33 Harness Adapter Kit

- FR-15.1 **external** (partly verified): Only Claude Code is run with its lockdown at the pinned version.
- FR-15.2 **external** (partly verified): Claimed in full only by the lockdown job of a release tag.
- FR-15.7 **external** (partly verified): Only Claude Code connects over TLS with what smcpctl clients setup wrote.
- FR-15.8 **external** (partly verified): Gemini CLI and Grok Build are not run; the matrix result is a full claim only from a release tag.
- FR-15.10 **external** (partly verified): Gemini CLI and Grok Build have no result in the matrix job.
- FR-18.3 **external** (no claiming test or record): Gemini CLI needs a GEMINI_API_KEY and Grok Build has no installable CLI, so their quick starts are not followed.
- SR-4.9-1 **external** (partly verified): Only Claude Code is started at its pinned version with a second server added.
- SR-4.11-1 **external** (partly verified): Only Claude Code is started at its pinned version with its lockdown.

## Planned for v1.3.0

Every requirement with `TARGET: v1.3.0` (SRS Section 2.8: FR-20, FR-21, FR-22, FR-5.28 to FR-5.30 and the security requirements planned with them) that is not verified, grouped by primary element. Built from the status data of main `fe82231` (run https://github.com/ethan03805/Secure-MCP-Gateway/actions/runs/39412846028) by the phase-11 steward pass: 146 requirements target v1.3.0, 8 verified (FR-5.28, FR-5.29, FR-5.30, FR-20.51, FR-22.2, FR-22.3, FR-22.6, SR-3-6), 87 partly verified and 51 with no claiming test or record yet. The roll-up parents FR-20, FR-21 and FR-22 are not listed; they are verified when their children are. Of the 135 entries, 24 are marked missing, 104 unverified and 7 external. The claims of the Windows-only tests reach the status data only when the `windows (windows-latest)` job gets to its claim steps; in this run it stopped before them, at `internal/analytics.TestMetaMetricsSampling` (its bound is fixed by #196), so several FR-21 and Windows SR entries whose notes name Windows tests show no claim here. The planned requirements are counted apart from the current requirement set and do not affect the release label; they become part of it when v1.3.0 is released.

### E-01 Harness Interface Endpoint

- FR-21.8 **unverified** (no claiming test or record): Conformance requests run over the named pipe on Windows; the fixtures of both protocol eras compared with the TLS listener and the AF_UNIX scan are not complete.
- SR-2.8-6 **unverified** (no claiming test or record): The DACL, the first-instance flag and `pipe_squatted` are tested; a connection over SMB (`\\localhost\pipe\`) and as a user outside the group are not.

### E-02 Protocol Mediator

- SR-5.6-3 **unverified** (no claiming test or record): The general refusal of resources, prompts and server requests applies to hosted packages, but no bundled-instance stand-in test exists.

### E-03 Identity & Authentication Service

- FR-21.9 **unverified** (no claiming test or record): SID mapping by impersonation and the key check are tested in the per-user mode; the machine mode and the recorded refusals with the client SID are not.

### E-05 Policy Administration Service

- FR-21.23 **unverified** (no claiming test or record): `internal/durable` uses flushed write-through renames on Windows (tested); the file-layer hook over policy activation, registry and restore is not.

### E-08 Access Enforcement Point

- FR-22.35 **unverified** (partly verified): A granted hosted call carries the pipeline events; the ungranted call and the harness token sent directly to the instance are not in the same test.

### E-10 Tool Dispatcher

- FR-22.36 **unverified** (partly verified): Hosted calls use the southbound HTTP client with the package token; the conformance fixtures against the bundled instance are not run.
- SR-2.10-2 **unverified** (partly verified): Hosted calls carry only the package token; a capture of every request from E-10 and E-36 during a reconciliation is not made.

### E-12 Enforcement Coordinator

- FR-21.7 **unverified** (no claiming test or record): Service Control Manager stop and the named stop event are tested; the console `CTRL_C`, `CTRL_BREAK` and `CTRL_CLOSE` events and the exit times are not.
- SR-4.1-3 **unverified** (no claiming test or record): Profile and SID naming are tested; the token inspection of `smcpd` and two backends on a machine-mode host is not recorded.

### E-14 Local Server Registry

- FR-22.13 **unverified** (partly verified): Imported packages are verified and disabled; the active policy revision and session catalogs are not checked after import.
- SR-3.8-2 **unverified** (partly verified): Tool-list drift suspends the revision (tested); a start from a different verified image is not.

### E-15 Server Runtime Manager

- FR-21.11 **unverified** (partly verified): `CreateProcess` with C runtime quoting, the job attached at creation and the shell refusal are tested; one claim does not cover the package enablement with every argument form through a running Gateway.
- FR-21.12 **unverified** (partly verified): Memory, process and CPU limits and kill-on-close are tested on Windows runners; the hostile fixtures through a running Gateway with the CP-24 values are partly covered.
- FR-21.25 **unverified** (no claiming test or record): The path rules are tested on every platform (`internal/winpath`) and on Windows; the junction pointing outside the root and the request-filter fixtures compared with Linux are not claimed in full.
- FR-22.8 **unverified** (no claiming test or record): A local-entry package is an ordinary package, but no test enables one with the bundled instance stopped and running and checks that the instance receives nothing.
- FR-22.24 **missing** (no claiming test or record): The Enforced-profile containment of the instance (rootless Podman under an E-16 profile, own CP-46 identity, network namespace limited to E-18 endpoints) is not built; the instance runs as a hardened container with `contextforge_unconfined`.
- FR-22.25 **unverified** (partly verified): The container form is tested with Docker; the managed-process form exists only as the Windows Job Object primitive (FR-22.20 is not built), and on Windows the Connector does not yet choose it over a container. SRS changed in this pass to allow the container form.
- SR-4.8-2 **unverified** (partly verified): Enablement and launch refuse every interpreter form; a process-creation trace of a full Windows test run is not made.

### E-16 Execution Sandbox

- FR-21.13 **unverified** (partly verified): Per-revision AppContainer profiles, grants and `partially_confined` are tested on the Windows runner; the hostile fixtures through a machine-mode Gateway are not.
- SR-4.5-4 **missing** (no claiming test or record): No network namespace for the bundled instance; part of FR-22.24.
- SR-4.6-2 **unverified** (partly verified): Grants follow enablement and are revoked (Windows test); a write to a read-only root through a running machine-mode Gateway is not tested.
- SR-4.7-3 **missing** (no claiming test or record): Not tested; the container gets no engine socket or host namespace, but the E-16 profile of FR-22.24 is not built.

### E-18 Egress Broker

- FR-21.14 **unverified** (partly verified): WFP filters and the fixed proxy port are tested on the Windows runner; the hostile egress fixtures through a machine-mode Gateway and the removal on disable are not.
- FR-22.40 **missing** (no claiming test or record): No E-18 endpoint per hosted package; the bundled instance reaches hosted servers directly.
- SR-4.5-3 **unverified** (no claiming test or record): Filters in the Gateway provider and sublayer block a contained process except the broker port (Windows test); `smcpctl uninstall` removing them is not tested.

### E-19 Secret Vault

- SR-2.13-4 **unverified** (no claiming test or record): The vault master key is a DPAPI blob in the per-user mode; decryption as another account and from another host, and the passphrase option, are not tested on Windows.
- SR-2.13-5 **unverified** (partly verified): The instance credentials are vault entries in the `component.` namespace; a D-16 dump after importing API-key hosted packages is not inspected (the probe secret, FR-22.15, does not exist).

### E-21 Audit & Evidence Service

- FR-22.39 **missing** (no claiming test or record): Call events do not carry the virtual-server ID, the instance version and digest or `via=contextforge`.
- SR-6.18-2 **missing** (no claiming test or record): Results from the bundled instance are not labelled server-asserted with the instance attribution.

### E-22 Key & Trust Anchor Manager

- FR-21.10 **unverified** (partly verified): Keys are DPAPI blobs and `key_protection` is raised for an undecryptable key; the copy of the state directory to a second runner is not done.

### E-23 Health & Safety Monitor

- FR-20.5 **unverified** (partly verified): The four gauges are tested on a running Standalone Gateway; the scrape on an Enforced installation and the metrics setting left by a real first-run setup are not checked together.
- FR-21.26 **unverified** (no claiming test or record): `GetDiskFreeSpaceEx` feeds the free-space checks (Windows test); a running Gateway with a nearly full volume is not tested.
- SR-4-2 **unverified** (partly verified): Labels and modes are tested per place; a WSL2 installation running as a systemd service (needs FR-21.15) and the `high` package refusal in each mode are not.

### E-24 Management Console & Control API

- FR-20.48 **unverified** (partly verified): The catalogue holds every reason code with its Table B.2 text and every desktop code; the console (`console/src/messages.ts`) and the desktop windows import it, but no test claims that neither build holds a differing copy.
- FR-20.49 **unverified** (no claiming test or record): `docs/design/writing.md` exists and `tools/uilint` applies its banned list; the inspection of 30 strings is not recorded under `docs/verification/`.
- FR-20.50 **unverified** (no claiming test or record): `docs/design/visual.md` exists; the inspection of the desktop windows, five console views and the site pages in both schemes is not recorded.
- FR-21.1 **unverified** (partly verified): The version refusal is tested; the Windows acceptance subset (FR-21.20) does not exist yet, so neither runner reaches the SR-4-2 state through it.
- FR-21.2 **unverified** (no claiming test or record): The `windows` CI job cross-builds and vets every package and runs the `TestWindows*` fail-closed tests, without an FR-21.2 claim.
- FR-21.3 **external** (no claiming test or record): `.goreleaser.yaml` builds both zips and lists them in the checksum file; needs the inspection of a release that has them (none yet).
- FR-21.4 **unverified** (no claiming test or record): `tools/installps1` runs the refusal cases on `windows-latest`; the claim is full only when both verifiers and both invocations ran.
- FR-21.6 **unverified** (partly verified): The per-user task and Run-key fallback and the machine-mode service are installed by the Windows smoke scripts; restart after `smcpd` ends and the service start before logon after a reboot (Demonstration on a recorded host) are not recorded.
- FR-21.15 **missing** (no claiming test or record): The WSL2 installation mode is not built; it also needs a host with nested virtualization (recorded Demonstration).
- FR-21.19 **missing** (no claiming test or record): The `windows` jobs run on `windows-latest` and `windows-11-arm` and send their claims to the status data, but they are not required checks (a branch-protection change by the owner), run only part of `go test -short ./...`, and have no acceptance subset.
- FR-21.20 **missing** (no claiming test or record): No Windows acceptance subset and no per-mode results in the status data.
- FR-21.22 **unverified** (partly verified): The notices are in `install.ps1` and `docs/install.md`; the release notes statement needs a release, and the Mark-of-the-Web check through each invocation is partly claimed.
- FR-21.24 **external** (no claiming test or record): `windows-scan.yml` scans before publication; needs a release run with the recorded signature version and the EICAR test.
- FR-22.4 **unverified** (partly verified): G-15 lists, filters and renders catalog text inertly in Chromium, Firefox and WebKit against the fixture catalog; hostile HTML, formula and remote-image payloads are not all in the fixture.
- FR-22.5 **unverified** (partly verified): `smcpctl catalog` lists, shows and imports through a running Gateway; the comparison with G-15 for a hosted entry and the Auditor refusal are not in one test.
- FR-22.41 **unverified** (partly verified): G-15 shows the instance and Operator-only actions against a fixture; it is not driven through each state, and upgrade (FR-22.31) does not exist.
- SR-2.9-4 **unverified** (partly verified): Custom-scheme origins are refused; a console mutation from the desktop window passing the unchanged checks is not recorded.

### E-27 Observation Store

- FR-21.18 **unverified** (no claiming test or record): `smcpctl doctor` reports that DuckDB is unavailable; the JSON Lines store and the loopback-only Neo4j rule are not tested on Windows.

### E-28 Data Lifecycle & Memory Manager

- FR-21.5 **unverified** (partly verified): The per-user DACLs and the `state_acl` cause are tested on Windows; the machine-mode directories are not compared with CP-46 by `Get-Acl`.

### E-33 Harness Adapter Kit

- FR-21.16 **unverified** (no claiming test or record): The credential file location and DACL check are tested; the conformance fixtures through `smcp-stdio.exe` over TLS and the named pipe are not.
- FR-21.17 **missing** (no claiming test or record): `docs/clients/matrix.json` records no Windows paths, and `smcpctl clients setup`, `lockdown` and `doctor` have no Windows client paths.
- FR-21.21 **missing** (no claiming test or record): The real-agent suite does not run on Windows; the matrix has no Windows results.

### E-34 Desktop Application

- FR-20.1 **missing** (no claiming test or record): No Windows build (WebView2, control of the Service Control Manager service); the `desktop` CI job builds on macOS arm64 and Ubuntu x86_64 only, the Ubuntu arm64 build is not started against a Gateway, and no test claims the tray icon and console window on a running Gateway. The Windows 11 x64 start needs a recorded host (no hosted runner).
- FR-20.2 **unverified** (partly verified): States, accessible names and the Start, Stop and Restart rules are unit-tested on macOS and Linux; no harness drives a running Gateway through the seven states and opens each menu item; the Windows desktop application is not built.
- FR-20.3 **missing** (partly verified): launchd and systemd control is tested with fixed argument vectors and a stand-in service manager; Service Control Manager control on Windows is not built, and the polkit prompt on an Enforced host is not checked.
- FR-20.4 **unverified** (partly verified): Polling, staleness and the label are tested against a local endpoint; the 10-second tray change for health, emergency stop and approvals against a running Gateway is not measured; the Windows desktop application is not built.
- FR-20.6 **unverified** (partly verified): Origin and link handling are unit-tested; no test signs in through the window, checks a role-limited operation or opens the window twice.
- FR-20.7 **unverified** (partly verified): One notice per increase with the count only is unit-tested; native notifications and their activation at G-13 are not observed on each platform; the Windows desktop application is not built.
- FR-20.8 **unverified** (partly verified): Unit tests cover the password files, the two steps and failures; `desktop-e2e (linux)` completes setup against the real `smcpctl` and samples process arguments but records no claim; no run on macOS or Windows.
- FR-20.9 **unverified** (partly verified): The prerequisite check and the profile offer are unit-tested; setup is not run on Ubuntu hosts with and without rootless Podman; the Windows statement needs the Windows build.
- FR-20.10 **unverified** (partly verified): Detection, dry-run parsing and fixed commands are unit-tested; no runner with Claude Code and Codex CLI installed applies, connects and removes through the window.
- FR-20.11 **unverified** (partly verified): Tested against a local feed on macOS and Linux (anonymous request, schedule, offline); the Windows desktop application is not built.
- FR-20.12 **unverified** (partly verified): `smcpctl upgrade` and rollback reporting are tested with a stand-in; an upgrade from the previous release to a candidate from the menu is not run; the Windows desktop application is not built.
- FR-20.13 **unverified** (partly verified): Verification and the installer of the installed kind are tested against a test feed; an update of the previous release's application is not run end to end; the Windows `.msi` path is not built.
- FR-20.14 **unverified** (partly verified): Single instance and the start-at-login entries are unit-tested; start after a fresh login is not shown on each platform; the Windows desktop application is not built.
- FR-20.15 **external** (no claiming test or record): The `desktop` job runs axe (WCAG 2.2 AA) on the bundled windows in WebKit and Chromium but records no claim; keyboard-only setup, client setup and update are not tested; the VoiceOver, Orca and Narrator check of the tray items needs a person and is not recorded.
- FR-20.16 **external** (no claiming test or record): The timed task with three first-time users on each of macOS, Linux and Windows (see Blocked on the owner).
- FR-20.27 **unverified** (no claiming test or record): `docs/desktop.md` and `docs/install.md` cover most topics; Windows installation and removal are missing because the Windows build is, and no record of following the guide on each platform exists.
- FR-20.28 **unverified** (partly verified): Link parsing, refusal and argument delivery are unit-tested; the 64 KiB link and the absence of requests to the admin listener are not checked in a running application; Windows registration is not built.
- FR-20.40 **unverified** (no claiming test or record): The introduction exists (`desktop/src/intro*`); no test claims its content, the three tasks and their controls, and no inspection against `docs/design/writing.md` is recorded.
- FR-20.41 **unverified** (partly verified): The state machine is unit-tested; skipping with Escape at each step and Help, Introduction in the running application are not tested.
- FR-20.42 **unverified** (partly verified): Only the completed-or-skipped flag is stored (unit test); no run with the network disabled and a packet capture.
- FR-20.43 **external** (no claiming test or record): axe runs on the introduction in the `desktop` job without a claim; focus on the heading, the announced text and reduced motion are not claimed; the VoiceOver pass needs a person and is not recorded.
- FR-20.44 **external** (no claiming test or record): Part of the first-time-user task of FR-20.16 (see Blocked on the owner).
- FR-20.45 **unverified** (partly verified): The explanation of each state is unit-tested from the catalogue; the status window's controls are not driven through the seven states.
- FR-20.46 **unverified** (no claiming test or record): Empty states exist for client setup; no test opens every bundled window with an empty fixture, and the help texts are not inspected.
- FR-20.47 **unverified** (partly verified): Catalogue codes and setup and client failures are unit-tested; injected failures in the running application are not checked for the sentence limits, the details area and the copy control.
- FR-20.52 **unverified** (no claiming test or record): The bundled windows have dark-scheme and reduced-motion styles; the 2-second change on an appearance switch, the tray icon and the zero durations under reduced motion are not tested.
- SR-2-3 **unverified** (partly verified): Source checks show no secret, vault or control-API access in the application; no file-access trace (`fs_usage`, `strace -f`, Process Monitor) of a full run.
- SR-2-4 **unverified** (partly verified): The console window is incognito and setup files are deleted (unit tests); no test signs in, quits and searches the data directories for the cookie and password.
- SR-2-5 **unverified** (partly verified): Capability files and command registrations are checked; invoking each command from the console window's script context is not tested.
- SR-2-6 **unverified** (partly verified): The bundled CSP and the console origin rule are tested; no network capture of a full run and no injected remote script in a test build.
- SR-2.6-2 **unverified** (partly verified): Notifications have no actions and open only G-13 (unit tests); the signed-out, Operator and Approver decisions through the window are not run.
- SR-2-7 **unverified** (partly verified): Fixed argument vectors and elevation only for the package manager are unit-tested; the process is not observed on each platform; User Account Control on Windows is not built.
- SR-2.8-5 **unverified** (partly verified): Gateway-CA pinning and the error page are unit-tested with generated certificates; the console window is not pointed at test listeners with another CA, an expired certificate and another name.
- SR-7-2 **unverified** (partly verified): Every refusal case is tested against a test feed on macOS and Linux, with the real release key and cosign bundle; the Windows `.msi` path is not built.

### E-35 Platform Installers

- FR-20.17 **unverified** (partly verified): The `.dmg` is built and started by `installers-desktop-macos.yml` and the `.pkg` installed by `installers-macos-smoke.yml`, but neither result is a requirement claim (the build scripts are unit-tested). SRS changed in this pass: the `.pkg` carries the commands, the `.dmg` the application.
- FR-20.18 **unverified** (partly verified): `installers.yml` installs `smcp` and `smcp-desktop` on Ubuntu and Fedora for both architectures, and the other-version refusal for the `.deb`, without a requirement claim; the absence of graphical libraries is not checked.
- FR-20.19 **unverified** (partly verified): The AppImage is started on Ubuntu and Arch Linux by `scripts/desktop-smoke.sh` without a requirement claim; setup installing a systemd user unit from the AppImage and the release assets (no Flatpak) are not inspected.
- FR-20.20 **missing** (no claiming test or record): The `smcp` `.msi` (amd64, arm64) is built and smoke-tested; the `smcp-desktop` `.msi` with the application and the WebView2 bootstrapper is not built (no Windows desktop build). SRS changed in this pass: two packages, neither registers the service.
- FR-20.21 **unverified** (partly verified): Package contents and scripts are tested; installing each package over an existing installation and comparing the digests of configuration, keys, journal and backups is not run for every package.
- FR-20.22 **unverified** (partly verified): Removal of the Linux packages stops only the system service (tested); removal with `smcpctl journal verify` from a fresh install is not run on macOS and Windows.
- FR-20.23 **external** (partly verified): File names and the checksum listing are tested; needs the inspection of a release with every installer (`v1.3.0-beta.1` has no `.pkg`, `.msi` or Sigstore bundle).
- FR-20.24 **unverified** (no claiming test or record): `installers.yml` builds and smoke-tests each installer before the release job and `installers-broken.yml` shows a broken `.deb` stops it, without a requirement claim; the Windows desktop `.msi` is missing; the run of a candidate tag needs an inspection.
- FR-20.25 **missing** (no claiming test or record): `docs/install.md` shows the verification commands and the macOS prompt; the Windows SmartScreen, Unknown publisher and Smart App Control descriptions for the `.msi` and the screenshots are missing, and following the guide needs macOS 15 and Windows 11 hosts.
- FR-20.26 **unverified** (partly verified): Ad-hoc signatures are checked by `scripts/desktop-smoke.sh` on macOS without a requirement claim; the start after Open Anyway is not recorded.
- SR-4.11-2 **unverified** (partly verified): Package ownership is tested from the package definitions and `smcpctl doctor` reports writable binaries; a write attempt as the installing user on each installed package, and the `.msi` ACL check, record no claim.

### E-36 ContextForge Connector

- FR-22.1 **unverified** (partly verified): The pinned and operator catalog digests are checked; the run with outbound network blocked is not.
- FR-22.7 **unverified** (partly verified): The install text is never executed (source check and HFC-03); the marker-file fixture through a full import is not run.
- FR-22.9 **missing** (partly verified): The probe runs through the bundled instance, but not through an E-18 endpoint (FR-22.40) and without the probe secret of API-key entries.
- FR-22.10 **unverified** (partly verified): Manifest version 2, name mapping and renames are tested against the pinned image; the operator `low` refusal and the reverse-order probe are not in one claim.
- FR-22.11 **unverified** (partly verified): Provenance members are written for local and hosted imports; the inspection record of two imported packages is not made.
- FR-22.12 **unverified** (partly verified): The trust decision is presented and recorded; the decline through G-15 is not tested.
- FR-22.14 **unverified** (partly verified): Both events are recorded; `smcpctl journal verify` after a refused and a declined import is not run in the same test.
- FR-22.15 **missing** (no claiming test or record): No secret slot for API-key entries and no S1 binding at an E-18 endpoint.
- FR-22.16 **unverified** (partly verified): The `changed` mark is tested; the enabled revision serving unchanged and the re-import as a new revision are not tested together.
- FR-22.17 **unverified** (partly verified): The starter set is in the release lock and offered only with the bundled instance; the Demonstration is not recorded.
- FR-22.18 **missing** (partly verified): The release lock has no wheel set and is not signed with the release key; the advisory check at release is not recorded.
- FR-22.19 **unverified** (partly verified): cosign verification of the pinned image is tested against the network; the re-tagged unsigned image and another workflow identity are not.
- FR-22.20 **missing** (no claiming test or record): The managed-process form (wheel set, private virtual environment) is not built.
- FR-22.21 **missing** (no claiming test or record): The SBOM set has the catalog NOTICE only; the image and wheel SBOMs and the failing check for a missing identifier are not built.
- FR-22.22 **unverified** (partly verified): The choice, the configuration value and the refusals are tested; that no artifact is fetched on a no is not checked against the engine.
- FR-22.23 **unverified** (partly verified): The instance starts with a hosted revision and stops after it; the probe case and the 30-second bound are not claimed in one test.
- FR-22.26 **unverified** (partly verified): The listener is on loopback on a fresh port; the scan of non-loopback addresses and the Enforced firewall rule (not built) are missing.
- FR-22.27 **unverified** (partly verified): The generated configuration and the refusal of a changed key are tested against the pinned image; the route-family requests and the telemetry check are not all claimed.
- FR-22.28 **unverified** (partly verified): Generation, vault storage and the weak-credential refusal are tested; a token signed with a published key against the running instance, and generation at upgrade (FR-22.31), are not.
- FR-22.29 **unverified** (partly verified): Teams, users, tokens and the self-check are tested against v1.0.11; token renewal before expiry is not scheduled (a restart renews it).
- FR-22.30 **unverified** (partly verified): Starting, health checks, restarts and `contextforge_unhealthy` are tested; the timed first answer on an empty D-16 and a local tool succeeding during the outage are not.
- FR-22.31 **missing** (no claiming test or record): Upgrade with rollback is not built: `smcpctl contextforge` has no upgrade subcommand.
- FR-22.32 **unverified** (partly verified): `smcpctl contextforge uninstall` is tested; `smcpctl uninstall` removing the instance and `journal verify` afterwards are not.
- FR-22.33 **unverified** (partly verified): Reconciliation, suspension and the `Unknown tool` mapping are tested against the pinned image; the 5-second start after an unknown tool and every listed change in one run are not.
- FR-22.34 **unverified** (partly verified): One team, user, gateway and virtual server per package is tested; the gateway URL is the hosted URL, not an E-18 endpoint (FR-22.40).
- FR-22.37 **unverified** (partly verified): Plugins off and the doubled limits are checked; a hosted call at the Gateway's rate limit and with a withheld result is not.
- FR-22.38 **unverified** (partly verified): Reconciliation removes excluded objects (tested); the inspection of the admin client's operations is not recorded.
- FR-22.42 **unverified** (no claiming test or record): `docs/security-limitations.md` states the six points under Planned for v1.3.0; the inspection of a release candidate is not recorded.
- FR-22.43 **missing** (partly verified): The suite asserts HFC-02, HFC-03, HFC-04, HFC-06, HFC-10 and HFC-14, the console suite HFC-07, and the reconciliation tests part of HFC-08 and HFC-13; HFC-01, HFC-05, HFC-09, HFC-11 and HFC-12 are not asserted (they need E-18 endpoints, the probe secret or the Enforced containment).
- FR-22.44 **unverified** (partly verified): `smcpctl bootstrap` and `install` ask (tested), and the desktop first-run setup offers the box, unchecked by default, with the same notes and passes `--with-contextforge` only when it is checked (`desktop/src-tauri/src/contextforge.rs`, `desktop/test/contextforge-choice.test.ts`); the Demonstration of both setups is not recorded.
- SR-3.2-2 **unverified** (partly verified): The signature binding and its journal event are tested for the pinned image; images signed from another tag or repository are not.
- SR-3.5-2 **missing** (no claiming test or record): The probe is not limited to the entry's host through E-18 (FR-22.40).
- SR-3.6-2 **unverified** (no claiming test or record): Stdio transport is off in the generated configuration; no test watches processes and network during a hosted call.
- SR-4-3 **unverified** (no claiming test or record): The instance listens on loopback with authentication required; no test tries every port from the harness account with and without the harness token.
## History

The dated notes below record how the list changed, in the order they were added. Requirements named in them as open may since have been verified; the list above is the current state.

Updated on 2026-10-17 against the status data of `58a40c1`: entries that tests now verify or partly verify were removed (FR-1.39, FR-1.40, FR-1.49, FR-5.20, FR-5.24, SR-5.6-2, SR-7.2-1 and FR-19.1 after the hostile-suite fixes).

Updated on 2026-10-17 by the acceptance work: FR-11.1 and FR-10.11 are verified, FR-10.2, FR-12.2, FR-19.3 and SR-7.11-1 have partial claims, the FR-11 measurements have partial claims from the CI job `perf`, and FR-12.5 is deferred (Appendix N).

Updated on 2026-10-17 by the E-01 to E-04 partials sweep: SR-7.11-1 is verified (CP-09 connection and unauthenticated-work limits, slow headers and bodies, `internal/edge.TestPreParseBounds`).

Updated on 2026-10-17 by the egress-capability work: SR-5.16-1 is restored from Appendix N and verified (`TestEgressCapabilities`), and AT-10 is claimed by `TestAT10WebBroker`, so every scenario has a claiming test (FR-19.4). Whether the release label is "enforced" depends on the scenarios passing in the Enforced profile for the release commit (FR-19.3).

Updated on 2026-10-17 by the perf work: FR-11.4 is within its budget in the CI job `perf` (partial claim, no longer missing). The perf harness now takes P-213 from the request's receipt to delivery minus server execution to the backend's response; before, it ended server execution at the completed event, which follows response inspection, and so left response inspection out of FR-11.4 and FR-11.5.

Checked on 2026-10-17 against the status data of main `ee2e851` (386 verified, 117 partial, 26 unverified, none failing); every unverified requirement other than a parent is listed below, together with partly verified requirements whose missing part is external (reference hardware, a release, a person) needs a record rather than a test, or was a single named case (SR-7.9-1, since verified).

Updated on 2026-10-17 by the security-final work: SR-4.14-1 is implemented (`smcpctl remote enable` installs nftables host rules; verified by the root namespace test of the linux-integration job, partial claims elsewhere), SR-2.13-2 is narrowed and verified by an inspection record, SR-7.9-1 is verified by AT-19 (a server revision suspended before both rollbacks), and SR-3.6-1, SR-5.8-1, SR-5.9-2 and SR-6.2-1 are verified by new tests. SR-4.9-1 and SR-4.11-1 stay partial: they need each client started at its pinned version with a second server added (real-agent workflow).

Updated on 2026-10-17 by the partials-c sweep: FR-1.51, FR-17.3, FR-13.13 (verification narrowed to one schema version) and FR-10.34 (audit subgraph added; checked with pinned pyarrow, pandas and NetworkX in the CI go job) have verifying tests; none of them was listed.

Updated on 2026-10-17 by the verification records work: FR-18.8 (runbook executions, `runbooks/FR-18.8.md`), FR-14.5, FR-3.18 and FR-12.3 have records; FR-8.24, FR-8.30, FR-8.32, FR-8.33 and FR-13.3 are updated below. FR-14.9 is claimed by the `reference-packages` workflow's published result (partial on a branch, full on a release tag). After the merge, the `tap` workflow for v1.0.0-rc.2 (run 39074221187) and the `reference-packages` workflow on main (run 39074222847) published their results to `site-data/workflows.json`: FR-13.3 is verified by the tap run of a release tag (its line is removed), FR-14.9 is partial until the workflow runs on a release tag.

Updated on 2026-10-18 by the data partials work: FR-7.11 is verified by `internal/e2e` `TestHealthFaultEachDependency` (each dependency faulted in turn in a running Gateway; vault availability and decision-snapshot currency checks added, every check evaluated once per second).

Updated on 2026-10-18 by the data partials work: SR-7.8-1 is verified (`internal/backup` `TestRestoreVerifiesPolicyStoreReappliesRevocationsAndRebuildsGraph`).

Updated on 2026-10-18 by the data partials work: FR-17.7 is verified (`TestOpsKeyRotationUnderTraffic`; the SRS statement of the CA overlap was narrowed to what one TLS chain per handshake can serve).

Checked on 2026-10-17 by the phase-8 documentation pass against the status data of main `788c8b4` (529 requirements: 413 verified, 95 partial, 21 unverified, none failing). The 21 unverified are the 12 parents FR-3, FR-5, FR-7, FR-8, FR-11, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17 and FR-19 and the nine requirements marked external or missing below (FR-12.1, FR-12.8, SR-4.1-1, FR-18.6, SR-6.12-1, FR-12.4, FR-15.9, FR-16.10, FR-18.3). Every acceptance scenario passed in the Enforced profile for that commit (label "enforced"). The FR-11 figures below are from the CI job `perf` of that commit.

Updated on 2026-10-18 by the release-ops work: FR-19.3 has an Inspection record (`FR-19.3.md`), FR-19.4 is verified by `TestEveryScenarioHasEvidence` (it now reads the AT-07 annotation of the console suite), FR-14.9 is verified by the `reference-packages` run on tag v1.0.0 (run 39096364892, published to `site-data/workflows.json`), and the FR-12.1 and FR-12.8 entries record the inspection of the v1.0.0 release. SR-7.5-2 (the prompt on a pseudo-terminal, and `smcpctl install`) and FR-16.11 (Operator refused through a signed-in console account) are verified, FR-13.6 is claimed by the `install-standalone` job (macOS arm64 and Ubuntu without Podman, merged only when both report), and SR-4.1-1 is narrowed and has an Inspection record of the linux-integration run of PR #104 (`SR-4.1-1.md`). FR-18.6 has an Inspection record (`FR-18.6.md`: `@modelcontextprotocol/server-sequential-thinking` packaged by following the guide, imported, enabled and called), and FR-14.1 is claimed in full by `TestIntegrationPackageBuildEachType` in the linux-integration job (the OCI image is probed with rootless Podman). FR-13.8 is verified by `TestUpgradeAndRollback` (a failing migration added) and FR-13.12 by `TestEnforcedUninstallAndPurgeOnHost` on the Enforced CI host.

Updated on 2026-10-18 by the console partials work (part B): FR-8.22, FR-8.23, FR-8.26, FR-8.27, FR-8.28, FR-8.29, FR-8.31, SR-3.4-1 (narrowed: the bill of materials is the signed provenance statement) and SR-6.17-1 (fixtures written by `scripts/evidence-fixture`) have verifying console tests, and SR-2-2 and SR-2.5-1 verifying acceptance tests against the real `smcpd`; the FR-8.29 and FR-8.31 entries are removed.

Updated on 2026-10-18 by the remote-agents partials work: FR-12.13 and FR-16.9 are verified (`internal/conformance.TestConformanceThroughAdapters`). FR-15.9 and FR-16.10 are narrowed by an SRS change (live cloud-agent runs descoped from release 1.x) and verified by Inspection records. Parents with some evidenced children are now reported partial rather than unverified.

Updated on 2026-10-19 by the doctor work: FR-15.4 is verified by `cmd/smcpctl.TestDoctorEnforcedHostAsHarnessUser`. On the Enforced installation of the `linux-integration` job, doctor runs as the runner account (the harness user, not in group `smcp`), and then for a Standalone instance of the same user. Before this change doctor stopped at the unreadable Enforced configuration; it now checks the CP-46 Enforced directories as the harness user.

Checked on 2026-10-18 by the phase-9 steward pass against the status data of main `1a96b1c` (529 requirements: 457 verified, 68 partly verified, 4 unverified, none failing; v1.0.0 was released at 413, 95 and 21). The four unverified requirements are FR-11 (reviewed against a performance report on recorded hardware), FR-12.4, SR-6.12-1 and FR-18.3, each listed below; each parent not yet verified is reported partial. FR-9.17 is verified (smcpd answers `-31004` while the journal cannot be opened, then starts; AT-03). Every acceptance scenario passed in the Enforced profile for that commit (label "enforced"). The FR-11 figures below are from the CI job `perf` of `1a96b1c`. The lines below were checked against that status data: none of the listed requirements is verified yet.

Updated on 2026-10-19 by the secrets work: SR-2-1 is verified by `internal/secrets.TestSecretsNeverNorthbound`. Secrets are delivered in the S1 to S4 modes and echoed through results, tool errors, JSON-RPC errors and progress notifications. The test checks that none reaches the harness, the session API responses, the evidence or the diagnostic log.

Updated on 2026-10-18 by the v1.1.0 release: v1.1.0 (main `935dc4d`, release run 39178207151, rehearsed with v1.1.0-rc.2 on the same commit) is the first release built by the fixed pipeline. Its SBOMs and bundle were inspected: every SBOM entry has an OSI-approved license or a reviewed exception, and every archive carries the build recipe, the lockfiles, `PROVENANCE.md` and `THIRD_PARTY_NOTICES.txt`. FR-12.1 and FR-12.8 now have passing Inspection records (`inspections.md`) and their lines above are removed. FR-13.1 has a v1.1.0 record. The `tap` workflow passed for v1.1.0 on macOS and Ubuntu (run 39178720966), and `reference-packages` passed on the tag (run 39178206965); both results are published to `site-data/workflows.json` (FR-13.3, FR-14.9). The runbooks were executed again on `d55c08f` for FR-18.8 (`runbooks/`). In the CI status data of main `935dc4d` (529 requirements: 466 verified, 59 partly verified, 4 unverified, none failing; label "enforced") the four unverified requirements are still FR-11, FR-12.4, SR-6.12-1 and FR-18.3, listed above.

Updated on 2026-10-18 by the install-ops partials work: FR-13.5 is verified by `cmd/smcpctl.TestEnforcedInstallOnHost` on the linux-integration host, and FR-13.4 and FR-13.11 are claimed in full by `tools/reqreport.TestInstallProfilesEvidence` from the Standalone (macOS arm64, Ubuntu) and Enforced results of the same CI run. A Standalone `smcpctl uninstall` no longer removes the nftables table, AppArmor profiles, system units or service identities of an Enforced installation on the same host.

Updated on 2026-10-19 by the agents-partials work: the Real agents workflow has a `lockdown` job (`scripts/agents/lockdown.go`). Claude Code 2.1.302 follows its quick start (option B), connects over TLS with only what `smcpctl clients setup` wrote, and with the managed-settings lockdown applied a second MCP server in user and project scope does not load, the Read of the Gateway state directory and the Edit of its own `.mcp.json` are refused, and `smcpctl doctor` reports the extra servers (run 39184564500). The first run found that `smcpctl lockdown apply` wrote the managed file with mode 0600, which Claude Code ignored; it is now 0644. The job's result claims FR-15.2 and the matrix job's result claims FR-15.8 through `site-data/workflows.json` (partial from main, full from a release tag), and the broken-build check now runs every client. FR-15.1, FR-15.7, SR-4.9-1 and SR-4.11-1 stay partial: only Claude Code is locked down and run through `smcpctl clients setup` by CI; the lockdown mechanisms recorded for Codex CLI, OpenCode, Gemini CLI and Goose are not yet confirmed against their pinned versions.

Updated on 2026-10-18 by the perf work: the GitHub-hosted `ubuntu-24.04` standard runner class (x86_64, 4 vCPU, 16 GiB, SSD) is the recorded reference hardware of FR-11 (SRS §1.6, [reference-hardware.md](../reference-hardware.md)). `perf.json` records each run's processor, memory and disk, and a complete measurement within budget on that class is a full claim. The FR-11.2, FR-11.4, FR-11.5, FR-11.8 and FR-11.9 lines are removed. The CI job `perf` now also runs the FR-11.6 replay (2,000 records per second for 10 minutes through the analytics store writer into the DuckDB store, no backpressure signal) and the FR-11.8 analytics queries over the 30 days of observation data that replay writes. FR-11.9 now includes the graph engine (Neo4j, CP-33 budget). In the dispatch run 39190807816 of this branch (AMD EPYC 9V45, `referenceHardware` true), every measurement passed and was complete: FR-11.2 0.011 ms, FR-11.4 0.42 ms, FR-11.5 9.4 ms, FR-11.6 2,000 records/s with no offer at 80% queue occupancy and no drop, FR-11.8 458 ms p95 over 1,200,000 observation records and the 100,000-event journal, FR-11.9 1,541 MiB (smcpd 120 MiB, Neo4j 1,421 MiB). The earlier run 39187565839 on an EPYC 7763 runner measured FR-11.4 at 1.19 ms while Neo4j ran from the start of the job; the engine now starts after the FR-11.4 loads. On EPYC 7763 runners FR-11.4 had measured 0.52 to 0.95 ms before, so its margin stays thin there. FR-11 itself is reviewed by Analysis against a performance report and still needs a record that cites a passing `perf` run of main with every child verified. FR-11.6 and FR-11.8 are measured with the DuckDB store of the SRS stack. The release archives are built without cgo, and their JSON Lines fallback store is not measured at this volume.


Rebuilt on 2026-10-19 by the phase-10 steward pass: the per-element lines are now generated from the status data of main `383485d` and list every open requirement, partly verified ones included, with the missing part taken from the claiming tests' comments and the verification statement. The section below collects what only the owner can provide.

Updated on 2026-10-19 by the console partials work (part C): FR-8.16 is claimed in full (G-08 shows the in-process cache hit ratios and the Observation Store's memory against its budget, and edits both the Observation Store and graph memory budgets) and its line is removed. FR-8.30 has the `console-previous-browsers` job, FR-8.32 runs axe with the full WCAG 2.2 AA tag set, and FR-8.33 kills a real Runtime instance with the keyboard in the `console-enforced` job; their lines say what is still missing.

Updated on 2026-10-20 by the phase-11 steward pass: the section [Planned for v1.3.0](#planned-for-v130) lists each v1.3.0 requirement that is not verified, from the status data of main `fe82231`, with what it lacks, and [Blocked on the owner](#blocked-on-the-owner) gains the items those requirements need from the owner. The SRS was changed where the build deliberately differs: FR-20.1 and FR-20.20 (the desktop application and its `.msi` qualified on Windows 11 x64 only, a second `smcp` `.msi` without the application for every Windows host, and no installer registering the service, which FR-20.21 forbids), FR-20.17 and SR-4.11-2 (the release `.pkg` carries the commands, the `.dmg` the application) and FR-22.20 and FR-22.25 (outside the Enforced profile the bundled ContextForge instance runs as a hardened container when Podman or Docker is installed, and as the managed process otherwise and on Windows).

## Blocked on the owner

These open requirements cannot be closed by more code or CI work in this repository. Each needs something only the project owner can provide or decide. Everything else in the list above can be closed by a test, a record or a release run.

- **Three first-time users for the G-04 usability Demonstration** (FR-8.24). Needed: three people who have not used the console, each given the in-console help and the task "create and publish a scoped Observation Policy of at least 10 parameters" in the G-04 Observation & Parameter Workbench, timed from sign-in. The requirement passes when at least two finish within 10 minutes. The owner records each person's time and completion (names are not needed) as a Demonstration record in `docs/verification/FR-8.24.md`, which now holds the scripted run, in the format of `docs/verification/README.md`. The scripted run of the same task (`console/e2e/firsttime.spec.ts`, 16 actions in Chromium, Firefox and WebKit) is supporting evidence only. The alternative is an SRS change that accepts the scripted run as the verification.
- **A Gemini API key for the Gemini CLI runs** (FR-15.8, FR-15.10, FR-18.3, and the Gemini CLI part of FR-15.1, FR-15.7, SR-4.9-1 and SR-4.11-1). Needed: a Google AI Studio (Gemini API) key stored as the repository Actions secret `GEMINI_API_KEY`. The Vercel AI Gateway key the other clients use does not serve the Gemini API, and the Real agents workflow runs Gemini CLI only when this secret is set (`.github/workflows/agents.yml`). With the key, the matrix job gives Gemini CLI a result and its quick start can be followed at the pinned version.
- **A decision on Grok Build** (FR-15.8, FR-15.10, FR-18.3, FR-15.1). Grok Build is a local client of SRS Appendix K, but xAI publishes no installable Grok Build CLI, so no pinned version can be installed or run, and its configuration location and lockdown mechanism are unconfirmed. Needed: either a download location and terms that allow running a pinned Grok Build CLI in CI, or an owner decision to change Appendix K (drop Grok Build from the local clients, or record it as not runnable for release 1.x the way live cloud-agent runs were descoped in FR-15.9).
- **A real tunnel for the Remote Access Profile** (FR-16.1, FR-16.2, FR-16.8). The listener, the origin fields and the tunnel drivers are tested behind a local TLS stand-in and against fake `tailscale` and `cloudflared` binaries. FR-16.2 is a Demonstration with each of Tailscale Funnel and Cloudflare Tunnel on a test host, and FR-16.1 and FR-16.8 need calls through such a tunnel. Needed, either of: (a) the owner runs `smcpctl remote enable tailscale`, `smcpctl remote check` and a few calls through the public name on a host of the owner's tailnet (Funnel is already enabled there), then the same with `cloudflared`, and records the output; or (b) repository Actions secrets for an ephemeral, Funnel-enabled Tailscale auth key and for a Cloudflare named-tunnel token with a hostname on a zone the owner controls, so a CI job can run the Demonstration. Exposing a Gateway on a public name is the owner's decision, which is why this is not done from CI without them.

The items below block requirements planned for v1.3.0 ([Planned for v1.3.0](#planned-for-v130)). Everything else in that section can be closed by code, a test, a record or a release run.

- **First-time users on each platform for the desktop Demonstrations** (FR-20.16, FR-20.44). Needed: three people per platform (macOS, Linux and Windows 11, nine in all) who have not used the product, each starting from the downloaded installer with the in-application help, timed until Claude Code lists tools through the Gateway, without a terminal. Before setup each is asked what they will do next, and every question they ask the observer is noted. The requirements pass when at least two per platform finish within 15 minutes, name the three tasks of FR-20.40 and ask no next-step question. The owner records the times, answers and questions (names are not needed) under `docs/verification/`. The Windows part also needs the Windows desktop application, which is not built yet.
- **Screen-reader passes** (FR-20.15, FR-20.43). Needed: a person who uses VoiceOver (macOS), Orca (Linux) and Narrator (Windows 11) to confirm that each tray menu item is announced by name, and a recorded VoiceOver pass through the introduction. The axe checks are automated; the announcements are not.
- **A Windows 11 x64 host** (FR-20.1, FR-20.20, FR-20.25, and the Windows parts of the other FR-20 requirements). GitHub offers no Windows 11 x64 hosted runner (`windows-latest` is Windows Server 2025, `windows-11-arm` is arm64), and the owner qualified the desktop application on Windows 11 only. Needed: either a Windows 11 x64 machine on which the owner (or a self-hosted runner registered to this repository) starts the application, installs the `smcp-desktop` `.msi` and records the SmartScreen, Unknown publisher and Smart App Control prompts with screenshots; or an owner decision that `windows-latest` stands in for Windows 11 x64.
- **A macOS 15 host for the unsigned-installer guide** (FR-20.25). Needed: the owner follows `docs/install.md` on a Mac with macOS 15 or later, confirms the "Not Opened" dialog and the Open Anyway path for the `.pkg` and the `.dmg`, and adds screenshots.
- **A WSL2 host** (FR-21.15, and the WSL2 part of SR-4-2). Hosted runners have no nested virtualization. Needed: a Windows machine with WSL2 on which the WSL2 installation mode, once built, is run and recorded as a Demonstration.
- **A machine-mode reboot** (FR-21.6). Needed: a Windows host on which the owner installs the machine mode, reboots, and records that the `smcpd` service starts before anyone logs on.
- **Required Windows checks** (FR-21.19). Making the `windows (windows-latest)` and `windows (windows-11-arm)` jobs required is a branch-protection change that only the repository owner can make. They should be made required once the acceptance subset (FR-21.20) and the installer test run in them and pass reliably.
