# ContextForge catalog routes

Control API routes of the ContextForge Connector (E-36, SRS FR-22, planned for v1.3.0). They use the control API's bearer authentication, origin and content-type checks. Reads are open to the Administrator, Operators and Auditors; imports and trust decisions to the Administrator and Operators (FR-22.5). `smcpctl catalog --config <file>` uses these routes.

| Route | Roles | Purpose |
|---|---|---|
| `GET /api/v1/contextforge/status` | Administrator, Operator, Auditor | Catalog source (`catalog_origin` `pinned` or `operator`, release, SHA-256, entry count) or the reason it was refused; the release lock version and image digest; `bundled`; the catalog import key (`key_id`, `public_key`, `enrolled`, `classes`) |
| `GET /api/v1/contextforge/catalog` | Administrator, Operator, Auditor | Entries with class, unsupported reasons, entry SHA-256 and `import_state` (`not_imported`, `imported`, `changed`). Query parameters `class`, `category`, `auth_type` (exact, case-insensitive) and `q` (text search over id, name, provider, category, description, URL, install text and tags) |
| `GET /api/v1/contextforge/catalog/{id}` | Administrator, Operator, Auditor | One entry: the list view, every catalog field as data (`fields`) and the import draft (`draft`) |
| `POST /api/v1/contextforge/catalog/{id}/import` | Administrator, Operator | Start importing a local entry; answers `202` with a `proposal` in state `building` |
| `GET /api/v1/contextforge/proposals` | Administrator, Operator, Auditor | Proposals of this run, newest first |
| `GET /api/v1/contextforge/proposals/{id}` | Administrator, Operator, Auditor | One proposal: `building`, `ready` with its `decision`, `failed` with `reason_code` and `error`, or `decided` with `outcome` |
| `POST /api/v1/contextforge/proposals/{id}/decision` | Administrator, Operator | `{"accept": true, "presented_sha256": "<decision.sha256>"}` or `{"accept": false}` |

Catalog text is third-party data: show it as inert text and never load `logo_url` (FR-22.4).

## Importing a local entry

The import body:

```json
{
  "version": "0.0.41",
  "integrity": "sha512-...",
  "argv": ["node", "node_modules/@playwright/mcp/cli.js"],
  "licenses": ["Apache-2.0"]
}
```

| Member | Required | Meaning |
|---|---|---|
| `version` | yes | Exact artifact version; a range or dist-tag such as `latest` is refused with `UNPINNED_REFERENCE` (FR-22.6, FR-14.2) |
| `integrity` or `artifact_sha256` | yes | npm registry integrity, or the SHA-256 of the PyPI wheel |
| `artifact_type`, `package` | when the install text does not name them | `npm` or `pypi`, and the package name. The install text is only read to propose them (FR-22.7) |
| `argv` | yes | The launch vector inside the artifact; package runners and shells are refused (`UNPINNED_LAUNCH`) |
| `licenses` | yes | SPDX identifiers; the catalog has no license field |
| `runtime` | no | Defaults from the artifact type |
| `source` | no | Source reference, as in a packaging recipe |
| `risk_class` | no | `moderate` (default) or `high`; the catalog import key's anchor scope decides which are admitted |
| `side_effect` | no | Default side-effect class of every tool (default `external`); every tool's source trust is `untrusted` |

The Gateway then fetches the pinned artifact, probes it as `smcpctl package build` does, and records the ContextForge origin in the provenance statement (FR-22.11). When the proposal is `ready`, `decision.text` is the trust decision (FR-22.12): class, provider, repository, auth type, artifact, tools with their classes, risk class, side-effect classes, egress destinations and secret slots. Accepting it requires `presented_sha256` equal to `decision.sha256`; the Gateway then writes the decision (actor, time, text and its SHA-256) into the provenance statement's `trust_decision`, signs the package with the catalog import key, and imports it into the Library as verified-disabled without changing any policy grant (FR-22.13). A decision waits for one hour; after that the proposal is abandoned.

Each attempt records one `catalog_import` journal event (outcome `refused`, `imported`, `declined` or `abandoned`, with the entry ID and digest, class, catalog SHA-256, actor, reason and, on success, the server ID and revision), and each decision one `catalog_trust_decision` event (FR-22.14).

## The catalog import key

The Gateway creates a minisign key in `<state>/contextforge/import-signing.key` (mode 0600) at its first start with this release. It signs only packages whose trust decision an operator accepted, and it admits nothing until an Administrator enrolls its public key as a trust anchor, once:

```sh
smcpctl catalog status --config smcp.toml       # shows key_id and the public key
# save the public key line to contextforge-import.pub, compare the key ID, then:
smcpctl trust add contextforge-import.pub --name contextforge-import --key-id <key_id> --classes moderate,high
```

Until then an accept is refused with `IMPORT_KEY_NOT_ENROLLED` and the proposal keeps waiting.

## Refusals

| Code | Status | When |
|---|---|---|
| `CATALOG_DIGEST_MISMATCH`, `CATALOG_INVALID` | 503 | The configured catalog was refused at start |
| `CONTEXTFORGE_DISABLED` | 409 | A hosted entry while `[contextforge] bundled` is false (FR-22.22) |
| `HOSTED_IMPORT_UNAVAILABLE` | 409 | A hosted entry while the bundled instance is enabled: the hosted probe is not built yet |
| `CATALOG_ENTRY_UNSUPPORTED` | 409 | The entry is `unsupported`; the message gives its reasons |
| `UNPINNED_REFERENCE`, `UNPINNED_LAUNCH`, `SOURCE_EVIDENCE_MISSING`, `MANIFEST_SCHEMA` | 409 | The pins or launch vector are incomplete |
| `SANDBOXED_PROBE_UNAVAILABLE` | 409 | Servers run in the sandbox (`[runtime] sandbox = "podman"`) and the import probe cannot be sandboxed by the Connector yet |
| `DECISION_TEXT_MISMATCH`, `IMPORT_KEY_NOT_ENROLLED`, `not_ready`, `not_found` | 409, 404 | Decision refused; the proposal is unchanged |
| `role_refused` | 403 | The account's role may not import (journal `ADMIN_ROLE_REFUSED`) |
