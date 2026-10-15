# MCP Servers — FloorPlan

Updated: 2026-10-15

Scope: `/home/netrisk/Projects/mcp-servers`. Apply the parent `/home/netrisk/Projects/Agent.md` instructions. This map covers directories used by the authorized documentation and local version-control task. No unrelated project directory is changed.

| Path | Contents | Access / purpose |
|---|---|---|
| `architecture.md` | Architecture revision 2.0: Neo4j CE design, data flows, licenses, engineering server catalog, GUI and Hermes/client integration procedures | Current design; implementation remains pending |
| `ArchitectureV2.md` | Architecture V2.1 draft (2026-10-14): logical decomposition into 10 subsystems / 32 elements (E-xx) incl. graph Data Server and Observation & Analytics, 93 functions (F-xx), 11 external (X-xx) and 39 internal (I-xx) interfaces, 13 data stores, 14 GUI view modules (G-xx), session Allow-policy model, secrets design, sigma-based behavior baselines/anomaly scoring, Parameter Catalog and meta-metrics, research capture/export, V1→V2 traceability. Assumes external curation system + signed Trusted MCP Server Library and harness-specific adapters | Allocation baseline for SRS V2; proposed, not implemented |
| `MCP_Gateway_Security_SRS.md` | Security-control SRS, V1 (renamed from `MCP_Gateway_SRS.md`); 150 hierarchical controls; root of security MUSTs | Parent of all SR requirements in the implementation SRS |
| `Secure_MCP_Gateway_SRS.md` | Implementation SRS V1.0 draft (2026-10-15): open-source tech stack; 277 functional (FR) and 157 security (SR) requirements allocated to ArchitectureV2 elements/functions/interfaces; SR parented to security-SRS MUSTs; coverage, allocation and index appendices. **Generated — edit `srs_build/`** | Coding baseline (draft, pending owner review) |
| `srs_build/` | Requirement source records (`req*.txt`), front matter, appendices and `gen.py` validator/generator for `Secure_MCP_Gateway_SRS.md` | Edit sources here and rebuild; see `srs_build/README.md` |
| `Skills.md` | Requirement-development skill (INCOSE GtWR + project MUST/SHALL rules) | Use when creating or refining requirements |
| `mcp-spec/` | Unmodified local reference copy of the official MCP specification, latest released version 2026-07-28 (spec MDX, `schema.ts`/`schema.json`, examples, upstream LICENSE); `README.md` records source, commit and checksum | Read-only external reference; replace by adding a new version subdirectory |
| `versions/` | Immutable `MCP_Gateway_SRS_V1.md` snapshot and `MCP_Gateway_SRS_V1.validation.json` document-check evidence | Preserve released snapshots; add a new version for later baselines |
| `CHANGELOG.md` | Baseline history and future versioning procedure | Update with each approved document revision |
| `Secure-MCP-Gateway-Research-Brief.md` | Original September 21, 2026 research and recommendations | Preserved unchanged; historical claims require current validation |
| `archive/` | Original `Secure-MCP-Gateway-Architecture.md` and pre-split `architecture-pre-srs-v1-2026-10-04.md` | Historical reference, preserved byte-for-byte; do not edit |
| `work/` | Ignored drafts, candidate/numbered requirement records, generation and validation scripts, prior validation evidence | Intermediate documentation work; not production configuration or runtime test evidence |
| `.git/` | Local Git history and annotated version tags | Local history and tags; remote `origin` = https://github.com/netrisk2025/Secure-MCP-Gateway (public; created 2026-10-14) |
| `.gitignore` | Exclusions for work material, secrets, graph data, audit payloads, model weights and source caches | Keep sensitive/runtime artifacts out of documentation history |

Future source/deployment directories shown in the architecture are planned only. No production application, Neo4j database, MCP server, overlay or client configuration was installed or altered by this documentation task.
