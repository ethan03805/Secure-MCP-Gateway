# Secure MCP Gateway

A local reference monitor and research instrument for agentic frameworks that use the Model Context Protocol. The Gateway decides what a tool call may do before any server code runs, contains and watches the server while it runs, and inspects what comes back before the agent sees it. It records enough about every call to learn what normal looks like, so the same system doubles as an instrument for studying how agents use tools.

**Status:** specified, not implemented. This repository holds the architecture, the security-control baseline and a generated implementation SRS. There is no Gateway code yet.

**Website:** the specification is rendered at the project site (see `site/`). Every count, element page and requirement on the site is read from the documents in this repository at build time.

## Start here

| Read | For |
|---|---|
| `ArchitectureV2.md` | The logical decomposition: 10 subsystems, 32 elements, 93 functions, 50 interfaces, 13 data stores, the session Allow-policy model, secrets design and the anomaly method |
| `Secure_MCP_Gateway_SRS.md` | The implementation baseline: 434 SHALL requirements allocated to the architecture. Generated from `srs_build/`; edit the sources, not the output |
| `MCP_Gateway_Security_SRS.md` | The 150 security controls that parent every security requirement |
| `Client-Compatibility-Brief.md` | What Claude Code, Codex CLI and Hermes expect today, and where the specification must change to meet them |
| `architecture.md` | The problem-space analysis behind the design: threats, Neo4j Community Edition limits, protocol pitfalls, race control |
| `FloorPlan.md` | What every file in the repository is for |
| `CHANGELOG.md` | Baseline history and the revision procedure |

## Rebuilding the SRS

```
python3 -I srs_build/gen.py . Secure_MCP_Gateway_SRS.md
```

The build fails on any traceability error and warns on coverage gaps against the architecture and the security SRS.

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
