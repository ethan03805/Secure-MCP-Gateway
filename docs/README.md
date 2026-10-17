# Documentation

User and operator documentation for the Secure MCP Gateway, and the data files that the SRS references. The documentation set is specified by SRS FR-18; the table shows which documents exist today.

## Scope of v1

- The Gateway relays MCP **tools** only. Resources and prompts are not supported; sampling, elicitation and roots are refused unless the MRTR Relay Profile is enabled.
- Backends are **local** MCP servers that the Gateway launches from signed packages. Remote (hosted) MCP servers cannot be used as backends in v1.
- macOS runs the Standalone (unconfined) profile, labelled "not enforced". Server containment requires the Enforced profile on Linux.

## Documents

| Document | Requirement | Status |
|---|---|---|
| [Security Limitations](security-limitations.md) | FR-18.2 | Written |
| [Troubleshooting and reason codes](troubleshooting.md) | FR-18.7 | Written |
| [Client quick starts](clients/README.md) | FR-18.3 | Written; procedures that use unreleased commands are marked |
| [Console visual rules](console-style.md) | FR-8.35 | Written |
| [Tool-call approvals](approvals.md) and [approvals control API](api/approvals.md) | FR-3.14 to FR-3.24, FR-18.4 (part) | Written |
| [Request and response filters](filters.md) | FR-4.4 to FR-4.18, SR-5.9-2, FR-1.52 | Written |
| [Management console](console.md) and [console control API](api/console.md) | FR-8.1 to FR-8.35 (part), FR-18.4 (part) | Written for the views built so far |
| [Verification records](verification/README.md) | FR-19.4, FR-18.8 | Format defined; no records yet |
| [Flows](flows/) | — | Sequence diagrams of the main flows, each with the current implementation's differences |
| [Server sandbox](sandbox.md) | FR-12.3, FR-13.5, SR-4.5-1 to SR-4.7-2 | Written: enforced-profile prerequisites, Linux installer, `[runtime]` configuration, sandbox profile, Runtime Monitor evidence, `smcpctl runtime` |
| [Control API: runtime](api/runtime.md) | — | Written: `/api/v1/runtime*` routes |
| Install guide (`install.md`) | FR-18.1 | To be written with the installer (FR-13) |
| Operator guide (`operator-guide.md`) | FR-18.4 | To be written with the control API and console |
| [Policy reference](policy-reference.md) | FR-18.5 | Written for Framework Profiles and Session Allow Policy Templates, the Policy Store and `smcpctl policy` |
| [Control API: policy routes](api/policy.md) | FR-18.5 | Written |
| Packaging guide (`packaging-guide.md`) | FR-18.6 | To be written with `smcpctl package` (FR-14) |
| Runbooks (`runbooks/`) | FR-18.8 | To be written with each procedure |

## Flows

| Flow | File |
|---|---|
| Tool call | [flows/tool-call.md](flows/tool-call.md) |
| OAuth sign-in | [flows/oauth-sign-in.md](flows/oauth-sign-in.md) |
| Approval in hold mode | [flows/approval-hold.md](flows/approval-hold.md) |
| Server packaging and admission | [flows/server-packaging.md](flows/server-packaging.md) |
| Cloud agent through a tunnel | [flows/cloud-agent-tunnel.md](flows/cloud-agent-tunnel.md) |
| Emergency stop | [flows/emergency-stop.md](flows/emergency-stop.md) |
| Evidence journal verification | [flows/journal-verification.md](flows/journal-verification.md) |

## Data files

| File | Contents | Used by |
|---|---|---|
| [schemas/manifest.schema.json](schemas/manifest.schema.json) | JSON Schema of the server package manifest (SRS Appendix J) | E-13 import, `smcpctl package` |
| [parameters.json](parameters.json) | Parameter Catalog: every observation parameter of ARCH §10.3 with its attributes (FR-10.37) | E-29, G-04, research export |
| [status/elements.json](status/elements.json) | Implementation state of each element E-01 to E-33: `implemented`, `partial` or `not-started` | CI status data, project site |
| [clients/matrix.json](clients/matrix.json) | Client matrix with pinned versions and latest results (FR-15.10) | Client matrix job, quick starts |

The SRS build (`srs_build/gen.py`) checks `parameters.json`, `schemas/manifest.schema.json` and `status/elements.json`. Update `status/elements.json` in the same pull request that changes an element's implementation state.
