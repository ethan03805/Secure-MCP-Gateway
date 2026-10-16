# Secure MCP Gateway

A local reference monitor between AI agent harnesses and Model Context Protocol (MCP) servers. The Gateway decides what a tool call may do before any server code runs, contains and watches the server while it runs (on Linux), and inspects what comes back before the agent sees it. It records signed evidence of every decision, and it records enough about every call to learn what normal looks like, so the same system is also an instrument for studying how agents use tools.

Licensed under the [Apache License 2.0](LICENSE). Security reports: [SECURITY.md](SECURITY.md).

## Status

**Specified in full; partly implemented.** The specification baseline is SRS V1.2 with architecture V2.3: built as specified, it is the finished v1 product. The code implements a first vertical slice (OAuth 2.1 sessions, policy decisions, dispatch to stdio MCP servers and a signed evidence journal). Of the 33 architecture elements, 17 are partly implemented and 16 are not started; `docs/status/elements.json` records the state and a note for each, and the requirement report produced by CI lists which requirements tests verify, partly verify, fail or leave unverified (FR-12.10).

No release has been published, and no build is labelled "enforced". A release is labelled "enforced" only when every acceptance scenario AT-01 to AT-21 passes on the Linux Enforced profile (FR-19.3).

## Scope of v1

- **Tools only.** The Gateway relays MCP tools. Resources and prompts are not supported; sampling, elicitation and roots are refused unless the MRTR Relay Profile is enabled.
- **Local backends only.** Every backend is a local MCP server packaged and signed by the operator (`smcpctl package`). Remote (hosted) MCP servers cannot be used as backends in v1.
- **Platforms.** Linux (x86_64, arm64) with rootless Podman, nftables, cgroup v2 and systemd runs the **Enforced profile**, which contains each server. macOS arm64, and Linux without those features, runs the **Standalone (unconfined) profile**: the same policy, inspection, approval and evidence controls, but no containment, health always `degraded: unconfined`, high-risk servers refused, and the label "not enforced".
- **Clients.** Claude Code, Codex CLI, Hermes, OpenCode, Gemini CLI, Goose and Grok Build connect locally. Grok Bot, ChatGPT agent "dots" and Meta Muse run on vendor computers and connect through the Remote Access profile, which exposes the Gateway on your computer through an authenticated tunnel.
- **Not mediated.** An agent's built-in shell, file, browser and connector tools do not use MCP and bypass the Gateway. See [docs/security-limitations.md](docs/security-limitations.md).

## Start here

| Read | For |
|---|---|
| `ArchitectureV2.md` | The logical decomposition: 10 subsystems, 33 elements, 99 functions, 56 interfaces (17 external, 39 internal), 15 data stores and 14 GUI view modules; the session Allow-policy model, secrets design, anomaly method and the authority, platform and remote-access assumptions |
| `Secure_MCP_Gateway_SRS.md` | The implementation baseline: 558 SHALL requirements (385 functional in 19 roots, 173 security), each allocated to the architecture, with the manifest schema, client matrix, hostile fixture suite and acceptance mapping as appendices. Generated from `srs_build/`; edit the sources, not the output |
| `MCP_Gateway_Security_SRS.md` | The 150 security controls that parent every security requirement |
| `docs/` | Security Limitations, troubleshooting and reason codes, client quick starts, flow diagrams, and the data files the SRS references (manifest schema, Parameter Catalog, element status, client matrix) |
| `Client-Compatibility-Brief.md` | What each supported client expects from an MCP server, and the evidence behind the client matrix |
| `architecture.md` | The problem-space analysis behind the design: threats, Neo4j Community Edition limits, protocol pitfalls, race control |
| `FloorPlan.md` | What every file in the repository is for |
| `CHANGELOG.md` | Baseline history, the reasons for each change, and the revision procedure |

The counts above are those printed by the SRS build (`srs_build/gen.py`) and found in `ArchitectureV2.md` at this commit.

## Running the first slice

The slice is the path a tool call takes from a harness to a backend server and back, with the controls the SRS puts on that path. It runs on macOS and Linux in the Standalone profile: backend servers run as plain subprocesses, health reports `degraded: unconfined`, and the sandbox, egress broker and installer are not implemented yet.

```
go build -o build/ ./cmd/...
./build/smcpctl bootstrap --dir ~/smcp
./build/smcpd --config ~/smcp/smcp.toml
```

`bootstrap` prompts for two passwords (12 or more characters, each entered twice): the Administrator, who uses the control API, and the Session Approver, who approves harness sign-ins. Passwords are never taken from the command line or the environment (SR-7.5-2). Without a terminal, pass `--admin-password-file` and `--approver-password-file`. With `--bootstrap-token`, no Administrator password is set; bootstrap prints a one-use token, valid for 24 hours, and `smcpctl admin redeem --config ~/smcp/smcp.toml` sets the password after smcpd starts.

`bootstrap` writes `smcp.toml` (harness listener on 127.0.0.1:8443, control API listener on 127.0.0.1:8444, Administrator, Session Approver, principals, OAuth clients, backend servers), `policy.json` (framework profiles and session allow templates) and `state/` (a local CA name-constrained to loopback names, the listener certificate, the Ed25519 evidence key, the operator token and the journal). The example configuration runs `smcp-refserver`, a read-only reference server built from `cmd/smcp-refserver`, on `~/smcp/sandbox`. Bootstrap looks for `smcp-refserver` next to `smcpctl`, then on `PATH`, and writes its absolute path into the configuration (`--refserver` overrides this); launch commands that resolve packages at run time, such as `npx` or `uvx`, are refused (SR-3.6-1).

To connect Claude Code:

```
export NODE_EXTRA_CA_CERTS=~/smcp/state/tls/ca.crt
claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
```

Claude Code discovers the Gateway's OAuth metadata and opens a browser. Sign in as the Session Approver `approver`; the Administrator account is refused there. The token Claude Code receives is the Gateway session (FR-2.20); the tools it lists are exactly those the session's template permits (SR-5.4-1), named `<alias>_<tool>` (FR-1.26), for example `ref_read_file`.

Other commands:

| Command | Does |
|---|---|
| `smcpctl health` | Reports health and the active profile |
| `smcpctl stop --reason <text>` | Emergency stop: every tool call is refused until resumed |
| `smcpctl resume` | Leaves emergency stop |
| `smcpctl policy reload` | Validates and activates `policy.json`; a changed document under an already active revision ID is refused |
| `smcpctl approvals` | Placeholder until the Approval Service (E-07) exists; approval-obligated calls are refused with `-31002` |
| `smcpctl journal verify` | Checks the hash chain, signatures and anchor of the evidence journal (FR-7.5) |
| `smcpctl config validate`, `smcpctl hash-password` | Validate a configuration; hash a password for an added Session Approver |

Each takes `--config ~/smcp/smcp.toml`. `stop`, `resume` and `policy reload` authenticate to the control API with the operator token in `state/keys/admin.token`.

What the slice does and does not implement is listed per element in `docs/status/elements.json`, per package in `internal/README.md`, and per flow in `docs/flows/`. The requirement report is built with:

```
make status        # writes build/reqreport.md, build/reqreport.json and build/status.json
```

`make check` runs locally what the required CI jobs check; `make integration` runs the end-to-end script that CI runs on Linux. See `scripts/README.md`.

## Rebuilding the SRS

```
python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md
```

The build fails on any traceability error, on unknown requirement or parameter references in the front matter and appendices, and on inconsistent `docs/` data files; it warns on coverage gaps against the architecture and the security SRS. Commit the regenerated SRS with its sources.

## Building the website

```
cd site
npm ci
npm run build      # static export to site/out
npm run dev        # local preview
```

The site is a static Next.js export. It parses `ArchitectureV2.md`, `srs_build/req*.txt` and `MCP_Gateway_Security_SRS.md` directly, so a change to any of them changes the site on the next build. Deployment is configured by `vercel.json` at the repository root.

## Reference material

`mcp-spec/` is an unmodified copy of the MCP specification release 2026-07-28, kept for citation. `versions/` holds immutable snapshots of released baselines. `archive/` holds superseded documents, preserved byte for byte.
