# MCP Servers — FloorPlan

Updated: 2026-10-16 (SRS V1.2 and architecture V2.3 re-baseline; `docs/`, license and security policy added)

Scope: this repository (`Secure-MCP-Gateway`). This map covers every top-level path. Paths are relative to the repository root.

| Path | Contents | Access / purpose |
|---|---|---|
| `README.md` | Entry point: what the product is, v1 scope, status, where to start reading, how to run the first slice and rebuild the SRS and the site | Keep in step with this file |
| `LICENSE` | Apache License 2.0, full text | Project license |
| `SECURITY.md` | How to report a vulnerability, supported versions, scope, release signing key | Public security policy |
| `CHANGELOG.md` | Baseline and implementation history with the reason for each change; revision procedure | Update with each document revision |
| `ArchitectureV2.md` | Architecture V2.3 draft: 10 subsystems, 33 elements (E-01 to E-33), 99 functions (F-01 to F-99), 17 external (X-01 to X-17) and 39 internal (I-01 to I-39) interfaces, 15 data stores (D-01 to D-15), 14 GUI view modules (G-01 to G-14); session Allow-policy model, secrets design, behavior baselines and anomaly scoring, Parameter Catalog, platform profiles, policy and evidence authority, Remote Access profile | Allocation baseline for the SRS; implementation state per element is in `docs/status/elements.json` |
| `Secure_MCP_Gateway_SRS.md` | Implementation SRS V1.2 draft: technology stack, platform and conditional profiles, 558 requirements (385 FR in 19 roots, 173 SR) allocated to the architecture, SR parented to security-SRS MUSTs; appendices A to M (controlled parameters, error and reason codes, roles, graph mirror model, coverage, allocation, index, set checks, manifest schema, client matrix, hostile fixtures, acceptance mapping). **Generated — edit `srs_build/`** | Coding baseline |
| `srs_build/` | Requirement source records (`req*.txt`), front matter, appendices (`appendix.md`, `appendix2.md`) and `gen.py`, the validator and generator for `Secure_MCP_Gateway_SRS.md` | Edit sources here and rebuild; see `srs_build/README.md` |
| `MCP_Gateway_Security_SRS.md` | Security-control SRS V1: 150 hierarchical controls, 122 of them MUST; root of every SR; Appendix B acceptance scenarios AT-01 to AT-21 | Parent of all SR requirements |
| `docs/` | Security Limitations, troubleshooting and reason codes, client quick starts and `clients/matrix.json`, console visual rules, verification record format, `flows/` (Mermaid sequence diagrams of seven flows with current implementation differences), `schemas/manifest.schema.json`, `parameters.json` (Parameter Catalog), `status/elements.json` (element implementation state) | User and operator documentation and data files the SRS references; `gen.py` checks the data files |
| `Client-Compatibility-Brief.md` | What each supported client expects from an MCP server: protocol eras, authentication hooks, lockdown mechanisms, and the cloud agents | Evidence for the client matrix (SRS Appendix K) |
| `architecture.md` | Architecture revision 2.0: problem-space analysis, Neo4j CE design, data flows, licenses, engineering server catalog, GUI and Hermes integration procedures | Background and rationale; superseded as an allocation baseline by `ArchitectureV2.md` |
| `Skills.md` | Requirement-development skill (INCOSE GtWR plus project MUST/SHALL rules) | Use when creating or refining requirements |
| `go.mod`, `go.sum` | Go module `github.com/ethan03805/secure-mcp-gateway` | Build with `go build ./...`; test with `go test ./...` |
| `cmd/` | `smcpd` (the Gateway daemon) and `smcpctl` (bootstrap, config validate, journal verify, health, hash-password) | First vertical slice; see README |
| `internal/` | Gateway packages by element: `edge` (E-01, E-02, E-08, E-12), `session` (E-03, E-04, OAuth 2.1), `policy` (E-05, E-06), `backend` (E-10, E-14, E-15), `audit` (E-21), `keys` (E-22), `config` (configuration schema), `ids`, `reqtest` (requirement tagging), `e2e` (end-to-end tests) | Implementation; each test declares the requirement IDs it verifies (FR-12.10) |
| `tools/reqreport/` | Reads `go test -json` output and writes the requirement-to-test report that CI publishes | FR-12.10 |
| `spikes/` | Experiments that retire SRS §3.3 stack risks; each has its own `go.mod` and a `README.md` recording the result | Evidence for design decisions; not part of the Gateway build |
| `site/` | Static Next.js website that renders the specification. Parses `ArchitectureV2.md`, `srs_build/req*.txt` and `MCP_Gateway_Security_SRS.md` at build time | Rebuild or redeploy after any document change |
| `vercel.json`, `.vercelignore` | Vercel deployment configuration for the site | Deployment only |
| `.github/workflows/` | Continuous integration: SRS regeneration check, site build, Go build and tests with the requirement report | Runs on every push and pull request |
| `mcp-spec/` | Unmodified copy of the MCP specification release 2026-07-28 (MDX, `schema.ts`/`schema.json`, examples, upstream license); `README.md` records source, commit and checksum | Read-only reference; add a new version subdirectory to update |
| `versions/` | Immutable `MCP_Gateway_SRS_V1.md` snapshot and its validation evidence | Released snapshots only; releases add new ones |
| `Secure-MCP-Gateway-Research-Brief.md` | Original September 21, 2026 research and recommendations | Preserved unchanged; historical claims need current validation |
| `archive/` | Original `Secure-MCP-Gateway-Architecture.md` and pre-split `architecture-pre-srs-v1-2026-10-04.md` | Historical reference, preserved byte for byte |
| `.gitignore` | Exclusions for local work, secrets, runtime state, build output and agent worktrees | Keep runtime and sensitive material out of history |
| `.git/` | Git history and tags (`mcp-gateway-srs-v1` marks the SRS V1 baseline) | Remote `origin` = https://github.com/ethan03805/Secure-MCP-Gateway |
