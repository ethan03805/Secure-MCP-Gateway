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

**Every architecture element has code; none is complete, and no release has been published.** The specification baseline is SRS V1.2 with architecture V2.3. Each element's state and main gaps are in [`docs/status/elements.json`](docs/status/elements.json); the requirement report that CI builds from the tests (FR-12.10) lists which requirements are verified, partly verified or not yet verified, and the project site shows both. Produce the report locally with `make status` (writes `build/reqreport.md`).

No build is labelled "enforced". A release is labelled "enforced" only when every acceptance scenario AT-01 to AT-21 passes on the Linux Enforced profile (FR-19.3). macOS always runs "not enforced".

Known issues that affect first use:

- The native Claude Code build and OpenCode (Bun runtime) reject the IP name constraints of the Gateway's local CA and do not connect over HTTPS. Use the `smcp-stdio` adapter for them ([docs/agents-conformance.md](docs/agents-conformance.md)).
- The installer and Homebrew have no release to download until the first tag; build from source.

## Scope of v1

- **Tools only.** The Gateway relays MCP tools. Resources and prompts are not supported; sampling, elicitation and roots are refused unless the MRTR Relay Profile is enabled.
- **Local backends only.** Every backend is a local MCP server packaged and signed by the operator (`smcpctl package`). Remote (hosted) MCP servers cannot be used as backends in v1.
- **Not mediated.** An agent's built-in shell, file, browser and connector tools do not use MCP and bypass the Gateway. See [docs/security-limitations.md](docs/security-limitations.md).

## Profiles

| Profile | Where | What you get |
|---|---|---|
| **Enforced** | Linux x86_64 or arm64 with rootless Podman (crun), nftables, cgroup v2, systemd and AppArmor or SELinux | Policy, inspection, approvals and evidence, plus containment: each server in a rootless sandbox with no capabilities, a read-only root, resource limits and no network except the Egress Broker |
| **Standalone** | macOS, and Linux without those prerequisites | The same policy, inspection, approval and evidence controls, but servers run as ordinary processes; health is always `degraded: unconfined`, high-risk servers are refused, and the label is "not enforced" |

`[profile] mode = "auto"` (the default) picks Enforced when every prerequisite is present. `smcpctl runtime doctor` lists what a Linux host is missing.

## Install

```sh
# From a release (once one is published): verifies the SHA-256 checksum, installs to ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh

# Homebrew (once the tap exists)
brew install ethan03805/tap/smcp

# From source (Go, no Node.js needed)
git clone https://github.com/ethan03805/Secure-MCP-Gateway.git && cd Secure-MCP-Gateway
go build -o build/bin/ ./cmd/...
export PATH="$PWD/build/bin:$PATH"
```

The binaries are `smcpd` (the Gateway), `smcpctl` (the command-line tool), `smcp-refserver` (reference server), and the harness adapters `smcp-stdio`, `smcp-session` and `smcp-connect`. Release signature verification, the Linux enforced host setup, upgrades and removal: [docs/install.md](docs/install.md).

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
| [docs/README.md](docs/README.md) | Index of all user and operator documentation |
| [docs/install.md](docs/install.md), [docs/quickstart.md](docs/quickstart.md) | Installing and the first run |
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

The project site renders the specification, the element and requirement status, the flows and these documents.

## Verify

```sh
make check         # what the required CI jobs check: SRS build, go build, vet, gofmt, go mod tidy,
                   # go test -race -short, golangci-lint, site typecheck
make status        # full tests with coverage; writes build/reqreport.{md,json} and build/status.json
make integration   # bootstrap, run smcpd, drive an MCP client, rotate keys, back up, restore, upgrade
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
npm run build      # static export to site/out
npm run dev        # local preview
```

The site is a static Next.js export. It parses `ArchitectureV2.md`, `srs_build/req*.txt`, `MCP_Gateway_Security_SRS.md`, `docs/flows/` and the user documents directly, so a change to any of them changes the site on the next build. Deployment is configured by `vercel.json` at the repository root.

## Reference material

`mcp-spec/` is an unmodified copy of the MCP specification release 2026-07-28, kept for citation. `versions/` holds immutable snapshots of released baselines. `archive/` holds superseded documents, preserved byte for byte.
