# Secure MCP Gateway

A local reference monitor between AI agent harnesses and Model Context Protocol (MCP) servers. The Gateway decides what a tool call may do before any server code runs, contains and watches the server while it runs (on Linux), inspects what comes back before the agent sees it, and records signed evidence of every decision. It also records enough about every call to learn what normal looks like, so the same system is an instrument for studying how agents use tools.

Supported harnesses are Claude Code, Codex CLI, Hermes, OpenCode, Gemini CLI, Goose and Grok Build on the same computer, and cloud agents (Grok Bot, ChatGPT agent, Meta Muse) through an authenticated tunnel. For every tool call the Gateway:

- authenticates the harness with OAuth 2.1 and binds it to a session whose template lists the tools it may use;
- decides each call against a signed policy (default deny, deny rules, rates, quotas, session taint) before any server code runs;
- inspects arguments and results (path and URL canonicalization, secret fingerprints, Unicode controls, injection tagging, output schemas, size bounds);
- holds calls that need a person's approval and continues them when an Approver decides;
- launches each server from a signed package and, on Linux, runs it in a rootless Podman sandbox with network access only through an Egress Broker;
- delivers managed secrets to servers without exposing them to the agent;
- records signed, hash-chained evidence of every decision, and per-call observations from which it learns behavior baselines and scores anomalies.

Licensed under the [Apache License 2.0](LICENSE). Security reports: [SECURITY.md](SECURITY.md).

## Status

**Every architecture element of release 1.x (E-01 to E-33) has code and is wired into `smcpd`. Eight elements (E-07, E-09, E-12, E-17, E-18, E-23, E-30, E-31) are recorded as implemented: every requirement allocated to them is verified, none is deferred from release 1.0 and no other gap is known; the other 25 are partial (several have every requirement verified but carry requirements deferred from 1.0, E-16 ships without an SELinux module, and E-27 and E-32 have no Parquet in the release archives). E-34 Desktop Application, E-35 Platform Installers and E-36 ContextForge Connector, planned for v1.3.0, are built on main, together with the Windows port (FR-21: per-user, machine and WSL2 modes) and the southbound Streamable HTTP transport; what each planned requirement still lacks is in the [gap list](docs/verification/gap-list.md#planned-for-v130). Release v1.2.0 is published (2026-10-19, labelled "enforced"). The pre-releases v1.3.0-beta.1 and v1.3.0-beta.2 (2026-10-20) carry the Linux and macOS desktop packages, the ContextForge catalog and, in beta.2, the Windows zip archives and the `smcp` `.msi`; the Windows desktop application and its `.msi` are on main only. This README describes the main branch, whose changes since v1.2.0 are under Unreleased in [CHANGELOG.md](CHANGELOG.md). Pre-releases rehearsed each release (v1.0.0-rc.1 to rc.3, v1.1.0-rc.1 and rc.2, v1.2.0-rc.1).** The specification baseline is SRS V1.2 with architecture V2.5 (draft). Each element's state and main gaps are in [`docs/status/elements.json`](docs/status/elements.json); the requirement report that CI builds from the tests (FR-12.10) lists which requirements are verified, partly verified or not yet verified, and the project site shows both. Produce the report locally with `make status` (writes `build/reqreport.md`).

In the CI status data of main `44b4d60` (https://github.com/ethan03805/Secure-MCP-Gateway/actions/runs/39470420944), 488 of the 530 requirements of the current set are verified, 41 partly verified, 1 not verified and 0 failing; FR-13.4, FR-13.6 and FR-13.11 are partly verified in that run only because its macOS `install-standalone` job got no runner before the job timeout, and are verified in the run before (v1.2.0 was released at 491 verified, 38 partly verified and 1 not verified; v1.1.0 at 466, 59 and 4; v1.0.0 at 413, 95 and 21). Of the 146 requirements planned for v1.3.0, which are counted apart, 8 are verified, 107 partly verified and 31 have no claim yet. 2,279 tests ran, 0 failed and 30 were skipped, with 76% statement coverage. The requirement not verified: FR-18.3. Every open requirement is listed with what it lacks in [docs/verification/gap-list.md](docs/verification/gap-list.md), which ends with the items that only the project owner can unblock (first-time users for the usability Demonstrations of the console and the desktop application, a Gemini API key, a decision on Grok Build, a real tunnel for the Remote Access Profile, screen-reader passes, and Windows 11 x64, macOS 15 and WSL2 hosts).

A release is labelled "enforced" only when every acceptance scenario AT-01 to AT-21 passes on the Linux Enforced profile for the release commit (FR-19.3); the release workflow applies the label from the status data (`go run ./tools/reqreport label`). Every scenario has a claiming test in `internal/acceptance` or another suite ([docs/acceptance.md](docs/acceptance.md)). In the status data of main `44b4d60`, 21 of 21 scenarios pass in the Enforced profile and 20 in the Standalone profile, so that commit's label is "enforced"; v1.0.0, v1.1.0 and v1.2.0 were labelled "enforced" from the CI runs of their tagged commits (`docs/verification/FR-19.3.md`). An installation on macOS, or on Linux without the Enforced prerequisites, always reports "not enforced".

The latest CI figures (tests, coverage, requirement verification per element, acceptance scenarios per profile, performance measurements, real-agent results, hostile-fixture results and filter corpus rates) are on the project site's [Status page](https://secure-mcp-gateway-pearl.vercel.app/status/); the [Install page](https://secure-mcp-gateway-pearl.vercel.app/install/) shows the releases and the results of the tap and reference-package verification workflows, both passed for v1.1.0 and v1.2.0. The recorded reference hardware of FR-11 is the GitHub-hosted `ubuntu-24.04` runner class (4 vCPU, 16 GiB; [docs/reference-hardware.md](docs/reference-hardware.md)), and a complete measurement within budget on that class is a full claim. At `383485d` every FR-11 measurement of the CI job `perf` is within its budget (decision latency 0.016 ms p95, Gateway-added overhead 17.9 ms p95, observation overhead 0.41 ms, observation ingest 2,000 records/s, console queries 606 ms p95, idle memory, smcpd with the graph engine 1,547 MiB; 4 × INTEL(R) XEON(R) PLATINUM 8573C, the reference class, so each is a full claim).

The Real agents workflow runs each local client CLI through a Gateway and judges every scenario from the journal: Claude Code 2.1.302, Codex CLI 0.142.2, Hermes Agent 0.17.0, OpenCode 1.15.13 and Goose 1.55.0 pass sign-in, catalog, allowed, denied, approval and ungranted calls, and a lockdown job runs Claude Code through its quick start and with its managed-settings lockdown. Gemini CLI and Grok Build are not run: Gemini CLI needs a `GEMINI_API_KEY` CI does not have, and Grok Build has no publicly installable CLI. Live cloud-agent runs (Grok Bot, ChatGPT agent, Meta Muse) through the Remote Access Profile are descoped from release 1.x (FR-15.9); the Remote Access Profile is tested with a test tunnel, a recorded tunnel provider run and the conformance suite relayed through `smcp-connect`.

Known issues that affect first use:

- An installation bootstrapped before the CA fix still has a local CA with IP name constraints, which the native Claude Code build and OpenCode (Bun runtime) reject. `smcpd` warns at startup; `smcpctl keys rotate ca` replaces the CA ([docs/agents-conformance.md](docs/agents-conformance.md)).
- `install.sh` without `--version` installs the latest final release; a pre-release needs `--version` (GitHub's latest-release link skips pre-releases). The Homebrew tap formula is replaced by the release workflow of each final release.

## Scope of v1

- **Tools only.** The Gateway relays MCP tools. Resources and prompts are not supported; sampling, elicitation and roots requests from servers are refused (`-32601`, or `-31010` for an `InputRequiredResult`), because the MRTR Relay Profile is not implemented.
- **Local backends only.** Every backend is a local MCP server packaged and signed by the operator (`smcpctl package`). Remote (hosted) MCP servers cannot be used as backends in v1 up to v1.2.0. On main, for v1.3.0, a `[[server]]` with a `url` reaches a hosted server over Streamable HTTP ([docs/southbound-http.md](docs/southbound-http.md)), and hosted servers from the ContextForge catalog are reached through an opt-in bundled ContextForge instance ([docs/contextforge.md](docs/contextforge.md)).
- **Not mediated.** An agent's built-in shell, file, browser and connector tools do not use MCP and bypass the Gateway. See [docs/security-limitations.md](docs/security-limitations.md).

## Profiles

| Profile | Where | What you get |
|---|---|---|
| **Enforced** | Linux x86_64 or arm64 with rootless Podman (crun), nftables, cgroup v2, systemd and AppArmor or SELinux | Policy, inspection, approvals and evidence, plus containment: each server in a rootless sandbox with no capabilities, a read-only root, resource limits and no network except the Egress Broker |
| **Standalone** | macOS, Linux without those prerequisites, and Windows (on main for v1.3.0; the Windows service mode contains servers in AppContainers and reports `partially_confined`) | The same policy, inspection, approval and evidence controls, but servers run as ordinary processes; health is always `degraded: unconfined`, high-risk servers are refused, and the label is "not enforced" |

`[profile] mode = "auto"` (the default) picks Enforced when every prerequisite is present. `smcpctl runtime doctor` lists what a Linux host is missing.

## Install

```sh
# From a release: verifies the minisign signature of the checksum file (and the Sigstore bundle when
# cosign is installed), then the archive's SHA-256; installs to ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh -s -- --version v1.2.0

# Homebrew
brew install ethan03805/tap/smcp

# Debian, Ubuntu, Fedora, RHEL or macOS packages (.deb, .rpm, .pkg) from the release page,
# verified as in docs/install.md, or: install.sh --package (as root it also installs)

# Planned for v1.3.0, in the pre-releases: the desktop application (.dmg, smcp-desktop .deb,
# .rpm, AppImage and .msi) and Windows (install.ps1, smcp .msi); see docs/install.md

# Set up a per-user installation with a launchd agent or systemd user unit (Standalone),
# or, as root on Linux, the Enforced profile
smcpctl install

# From source (Go, no Node.js needed)
git clone https://github.com/ethan03805/Secure-MCP-Gateway.git && cd Secure-MCP-Gateway
go build -o build/bin/ ./cmd/...
export PATH="$PWD/build/bin:$PATH"
```

The binaries are `smcpd` (the Gateway), `smcpctl` (the command-line tool), `smcp-refserver` (reference server), the harness adapters `smcp-stdio`, `smcp-session` and `smcp-connect`, and `smcp-workload` (the FR-11 reference workload generator, in the release archives only). Release signature verification, the Linux enforced host setup, upgrades and removal: [docs/install.md](docs/install.md).

## Quick start

```sh
smcpctl bootstrap --dir ~/smcp           # asks for the Administrator and Session Approver passwords
smcpd --config ~/smcp/smcp.toml          # harness listener 127.0.0.1:8443, console 127.0.0.1:8444
smcpctl health --config ~/smcp/smcp.toml
```

`bootstrap` writes the configuration, an example policy, a local CA, the evidence key, and a signed package of the bundled read-only reference server, enabled as the only backend (tools `ref_echo`, `ref_time_now`, `ref_list_files`, `ref_read_file`).

Connect Claude Code with OAuth (a browser opens; sign in as the Session Approver `approver`):

```sh
export NODE_EXTRA_CA_CERTS=~/smcp/state/tls/ca.crt
claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
```

Connect Codex CLI, or any client, through `smcp-stdio`, which holds the session and trusts the Gateway CA itself:

```sh
smcpctl clients credentials --config ~/smcp/smcp.toml --client-id <client> --secret-file <file>
smcpctl clients setup codex --config ~/smcp/smcp.toml --dry-run
```

The confidential client this needs, approvals, emergency stop and journal verification are walked through in [docs/quickstart.md](docs/quickstart.md). Per-client pages: [docs/clients/](docs/clients/README.md).

## Documentation

| Read | For |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | Start here if you have not used the product: the first day and the everyday tasks |
| [docs/README.md](docs/README.md) | Index of all user and operator documentation |
| [docs/install.md](docs/install.md), [docs/quickstart.md](docs/quickstart.md) | Installing and the first run |
| [docs/desktop.md](docs/desktop.md), [docs/windows-port.md](docs/windows-port.md) | The desktop application and Windows, planned for v1.3.0 |
| [docs/operator-guide.md](docs/operator-guide.md) | Day-2 operation: approvals, policy publication, packages, secrets, backups, keys, upgrades, emergency stop, remote access |
| [docs/policy-reference.md](docs/policy-reference.md), [docs/packaging-guide.md](docs/packaging-guide.md) | Writing policies; admitting your own MCP servers |
| [docs/runbooks/](docs/README.md#runbooks-fr-188) | Emergency stop, revocation, policy rollback, key compromise, backup and restore, key rotation, upgrade rollback |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Every error and reason code with the next action |
| [`Secure_MCP_Gateway_SRS.md`](Secure_MCP_Gateway_SRS.md) | The implementation baseline: every requirement allocated to the architecture, with appendices (controlled parameters, error codes, roles, manifest schema, client matrix, hostile fixtures, acceptance mapping). Generated from `srs_build/`; edit the sources, not the output |
| [`ArchitectureV2.md`](ArchitectureV2.md) | The logical decomposition into subsystems, elements, functions, interfaces, data stores and GUI view modules |
| [`MCP_Gateway_Security_SRS.md`](MCP_Gateway_Security_SRS.md) | The security controls that parent every security requirement, and acceptance scenarios AT-01 to AT-21 |
| [`Client-Compatibility-Brief.md`](Client-Compatibility-Brief.md) | What each supported client expects from an MCP server |
| [`internal/README.md`](internal/README.md) | Go packages mapped to architecture elements, extension points and residual gaps |
| [`FloorPlan.md`](FloorPlan.md) | What every path in the repository is for |
| [`CHANGELOG.md`](CHANGELOG.md) | Baseline and implementation history with the reason for each change |

The [project site](https://secure-mcp-gateway-pearl.vercel.app) renders the specification, the element and requirement status, the acceptance scenarios per profile with the release label, the performance measurements, the console browser results, the hostile-fixture results, the real-agent results with per-agent notes, the control API reference generated from the Go sources, the published releases with their verification steps, the flows and every document under `docs/`.

The management console is served by `smcpd` on the admin listener (`https://127.0.0.1:8444`). Each Appendix C role signs in with its own account (Administrator, Operator, Policy Author, Auditor, Researcher, Approver, Session Approver) and sees only the views and actions its role allows; `GET /api/v1/openapi.json` describes every control API route ([docs/console.md](docs/console.md)).

## Verify

```sh
make check         # what the required CI jobs check: SRS build, go build, vet, gofmt, go mod tidy,
                   # go test -race -short, golangci-lint, site typecheck
make status        # full tests with coverage; writes build/reqreport.{md,json} and build/status.json
make integration   # bootstrap, run smcpd, drive an MCP client, rotate keys, back up, restore, upgrade
make hostile       # the hostile backend fixtures of SRS Appendix L; writes build/hostile.{md,json}
make conformance   # MCP conformance suite over the schema examples (FR-12.9); writes build/conformance.md
go test ./internal/acceptance/   # acceptance scenarios against the real binaries (docs/acceptance.md)
make console-e2e   # Playwright acceptance tests of the console against a real smcpd
```

Against a running instance: `smcpctl journal verify` checks the evidence journal's hash chain, signatures, key transitions and anchor; `smcpctl doctor` reports MCP servers configured in your clients that bypass the Gateway. `scripts/agents` runs real agent CLIs through a Gateway and judges each scenario from the journal ([docs/agents-conformance.md](docs/agents-conformance.md)). See `scripts/README.md` for the CI scripts.

## Rebuilding the SRS

```sh
make srs           # python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md
```

The build fails on any traceability error, on unknown requirement or parameter references in the front matter and appendices, and on inconsistent `docs/` data files; it warns on coverage gaps against the architecture and the security SRS. Commit the regenerated SRS with its sources.

## Building the website

```sh
cd site
npm ci
npm test           # unit tests of the document list
npm run build      # static export to site/out
npm run check-out  # every docs/ file has a page; every internal link and anchor resolves
npm run dev        # local preview
```

The site is a static Next.js export. It parses `ArchitectureV2.md`, `srs_build/req*.txt`, `MCP_Gateway_Security_SRS.md`, `docs/flows/` and every Markdown file under `docs/` directly, so a change to any of them changes the site on the next build. Deployment is configured by `vercel.json` at the repository root.

## Reference material

`mcp-spec/` is an unmodified copy of the MCP specification release 2026-07-28, kept for citation. `versions/` holds immutable snapshots of released baselines. `archive/` holds superseded documents, preserved byte for byte.
