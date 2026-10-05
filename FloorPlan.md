# MCP Servers — FloorPlan

Updated: 2026-10-04

Scope: `/home/netrisk/Projects/mcp-servers`. Apply the parent `/home/netrisk/Projects/Agent.md` instructions. This map covers directories used by the authorized documentation and local version-control task. No unrelated project directory is changed.

| Path | Contents | Access / purpose |
|---|---|---|
| `architecture.md` | Architecture revision 2.0: Neo4j CE design, data flows, licenses, engineering server catalog, GUI and Hermes/client integration procedures | Current design; implementation remains pending |
| `MCP_Gateway_SRS.md` | Current SRS, V1; 150 hierarchical requirements with sources and verification | Normative development baseline |
| `versions/` | Immutable `MCP_Gateway_SRS_V1.md` snapshot and `MCP_Gateway_SRS_V1.validation.json` document-check evidence | Preserve released snapshots; add a new version for later baselines |
| `CHANGELOG.md` | Baseline history and future versioning procedure | Update with each approved document revision |
| `Secure-MCP-Gateway-Research-Brief.md` | Original September 21, 2026 research and recommendations | Preserved unchanged; historical claims require current validation |
| `archive/` | Original `Secure-MCP-Gateway-Architecture.md` and pre-split `architecture-pre-srs-v1-2026-10-04.md` | Historical reference, preserved byte-for-byte; do not edit |
| `work/` | Ignored drafts, candidate/numbered requirement records, generation and validation scripts, prior validation evidence | Intermediate documentation work; not production configuration or runtime test evidence |
| `.git/` | Local Git history and annotated version tags | Created for requested SRS version control; no remote configured by this task |
| `.gitignore` | Exclusions for work material, secrets, graph data, audit payloads, model weights and source caches | Keep sensitive/runtime artifacts out of documentation history |

Future source/deployment directories shown in the architecture are planned only. No production application, Neo4j database, MCP server, overlay or client configuration was installed or altered by this documentation task.
