# MCP Gateway documentation changelog

## SRS V1 / architecture 2.0 — 2026-10-04

First separate system requirements specification: `MCP_Gateway_SRS.md`, with an immutable byte-identical snapshot at `versions/MCP_Gateway_SRS_V1.md`. The local annotated Git tag `mcp-gateway-srs-v1` identifies this baseline and its matching architecture.

- Split the former combined document into design/integration procedures and a normative SRS.
- Defined 150 hierarchical requirements, including 122 MUST control statements, source traceability, one verification method per requirement, and 21 acceptance scenarios.
- Selected Neo4j Community Edition for authoritative policy, routing and audit metadata, replacing the prior Casbin/SQLite authorities. Documented CE limits, deterministic graph evaluation, denial semantics, immutable version links, dispatch/revocation ordering and independently protected audit evidence.
- Specified GUI inspection of server source, licenses, build provenance, tool manifests, policy explanations and linked audits.
- Curated 11 local engineering server candidates or explicitly proposed adapters, with primary source/license references, containment restrictions and admission gates. None is represented as installed or admitted.
- Retained detailed Hermes gateway-only procedures and the qualified scope for Headscale, Codex CLI and Grok Bot feasibility.
- Preserved the previous combined architecture without byte changes at `archive/architecture-pre-srs-v1-2026-10-04.md`. The September architecture and research brief remain unchanged.
- Initialized local Git history with the pre-split baseline followed by this revision. No remote repository or push is required or configured by this task.

Validation evidence is in `versions/MCP_Gateway_SRS_V1.validation.json`. Document checks and research reviews do not establish runtime security or implementation compliance.

## Combined architecture 1.0 — 2026-10-04

Accepted and expanded the earlier research into a combined architecture/specification with Hermes integration, OSS licensing, GUI administration, security controls and acceptance procedures. This document is retained in the archive and in the initial local Git commit.

## Historical inputs — 2026-09-21

The original `Secure-MCP-Gateway-Architecture.md` is preserved in `archive/`. The original `Secure-MCP-Gateway-Research-Brief.md` remains at the project root.

## Future revision procedure

1. Edit the active SRS and architecture with impact/source/verification updates; preserve IDs for unchanged requirements and record retirements or replacements.
2. Assign the next SRS version, update the architecture revision and cross-references, and create a new immutable SRS snapshot under `versions/`.
3. Validate requirement structure, source traceability, example syntax and snapshot identity; retain the validation record.
4. Commit the complete matching baseline locally and add its version tag, such as `mcp-gateway-srs-v2`.
5. Leave V1's snapshot and tag unchanged. Keep secrets, database dumps, audit payloads and live runtime data out of Git.
