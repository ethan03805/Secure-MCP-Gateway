# ContextForge catalog and connector

The ContextForge Connector (E-36) lets an operator import servers listed in the IBM ContextForge catalog into the Trusted MCP Server Library (SRS FR-22, planned for v1.3.0). This page describes what is built so far. The design, measurements and requirement findings are in the [ContextForge spike report](contextforge-spike.md).

## Release lock

`packaging/contextforge.lock.json` pins exactly one ContextForge release for a Gateway release (FR-22.18):

| Member | Value in this release |
|---|---|
| `version`, `source.tag`, `source.commit` | `v1.0.11`, commit `077071bbb43599dd5ab9372ebdbb9a8e686a9816` of `github.com/IBM/mcp-context-forge` |
| `image.index_digest` | `sha256:e9639c030162d6cb2f9f188600dd69af8091ec62a7ce307d4a74f4d4f86873df` |
| `image.platforms` | `linux/amd64` and `linux/arm64` image digests |
| `signer` | the cosign keyless identity: GitHub Actions issuer, workflow `docker-multiplatform.yml` at `refs/tags/v1.0.11` |
| `catalog.sha256` | `f6be59e31f1017487c8c882fa86b2594214e50b7bcf784773a5a4e0651e91daa` (135 entries) |
| `starter_set` | `aws-knowledge`, `deepwiki`, `microsoft-learn-docs`: hosted entries with auth type `Open` whose tools are documentation search and reading (FR-22.17) |
| `wheels` | empty: the managed-process form (FR-22.20) is not built yet |

The lock and the catalog file of the pinned release are compiled into `smcpd` and `smcpctl` (`internal/contextforge/release/`; a test keeps the copy equal to `packaging/contextforge.lock.json`). A lock whose version is not an exact tag, whose digests are not full SHA-256 digests, or whose signer is not the release workflow at that tag is refused with `CONTEXTFORGE_LOCK_INVALID`.

## Reading the catalog

`smcpctl catalog` reads the catalog of the pinned release by default. The file's SHA-256 is compared with the release lock before it is parsed. To use another catalog file, pass it with `--catalog FILE` and the SHA-256 you confirm with `--sha256 HEX`; without the digest, or with a different one, the file is refused with `CATALOG_DIGEST_MISMATCH` and not parsed (FR-22.1). Nothing is fetched over the network.

The parser refuses the whole file with `CATALOG_INVALID`, naming the rule, when the file is larger than 4 MiB, has more than 2,000 entries, has a string longer than 4,096 characters, uses a YAML anchor, alias, explicit tag or merge key, nests deeper than 16 levels, holds more than one document, or has an entry without a unique `id` (FR-22.2). An alias bomb is refused without being expanded.

```sh
smcpctl catalog list                    # every entry, its class and, when unsupported, why
smcpctl catalog list --class hosted --json
smcpctl catalog show playwright-mcp     # every field as text; the logo is not loaded
smcpctl catalog import --dry-run deepwiki
smcpctl catalog list --catalog ./mcp-catalog.yml --sha256 <the digest you checked>
```

Terminal output replaces control and format characters in catalog text, so an entry cannot drive the terminal.

## Classes

Each entry gets exactly one class (FR-22.3):

| Class | Rule | Pinned v1.0.11 catalog |
|---|---|---|
| `local` | names a `repo` and an `install` command | 4 |
| `hosted` | `url` is `https` and there is no `install` command | 45 |
| `unsupported` | anything else, with the reasons: auth type needs OAuth 2.1 (planned for v1.4.0), a plain `http` URL to a non-loopback host, a missing required field (`name`, `provider`, `auth_type`), a missing or invalid URL on an entry that is not local, a repo without an install command or the reverse | 86 |

An `install` string is only read as text: it is split on spaces to propose an artifact type, name and version, never passed to a shell or package manager (FR-22.7). A string with shell syntax gets no proposal, and a dist-tag such as `@latest` is never taken as a version.

## Hosted tool names

ContextForge serves a hosted server's tools as `<gateway-slug>-<name>`. A hosted package's manifest records each tool's `backend_name` (what ContextForge serves) and its manifest `name` (`[A-Za-z0-9_]{1,47}`), derived as FR-22.10 states (`contextforge.MapToolNames`):

1. remove the `<gateway-slug>-` prefix;
2. replace every character outside `[A-Za-z0-9_]` with `_`;
3. when the result is longer than 47 characters, or equal to the result of another tool of the package, use its first 38 characters, `_` and the first 8 hexadecimal digits of the SHA-256 of the backend name.

The names depend only on the tool names, not their order. When two tools still map to the same name, the import is refused with `TOOL_NAME_COLLISION` naming both. The gateway name and slug are `smcp-<entry id>` and are fixed in the manifest's `upstream` member.

## Importing a local entry

With a running Gateway, `smcpctl catalog --config smcp.toml` and the control API (`docs/api/contextforge.md`) import a local entry. The operator supplies what the catalog cannot: the exact version and digest of the artifact, the launch vector inside it and its licenses (FR-22.6). The Gateway fetches that artifact, probes it as `smcpctl package build` does, and shows the trust decision: class, provider, repository, auth type, artifact, tools with their classes, risk class, egress destinations and secret slots (FR-22.12). Every tool's source trust is `untrusted`.

```sh
smcpctl catalog import playwright-mcp --config smcp.toml \
  --version 0.0.41 --integrity sha512-... \
  --argv node --argv node_modules/@playwright/mcp/cli.js --license Apache-2.0
```

On a terminal it asks you to type `accept`; otherwise pass `--accept <sha256 of the decision>` or `--decline`, or decide later with `smcpctl catalog decide`. An accepted package carries the decision and the ContextForge origin (catalog SHA-256, release, entry ID and digest, URL, repository, install text) in its signed provenance statement (FR-22.11), is signed with the Gateway's catalog import key and is imported verified-disabled with no policy change (FR-22.13). Its revision is `<version>+cf.<n>`, so a re-import after the catalog changed is a new revision with its own decision. The entry then shows `imported`, or `changed` when the catalog's digest of it differs from the imported one (FR-22.16). Each attempt and decision is in the journal (`catalog_import`, `catalog_trust_decision`, FR-22.14).

An Administrator enrolls the catalog import key once, as `docs/api/contextforge.md` shows; until then an accept is refused with `IMPORT_KEY_NOT_ENROLLED`. Enabling an imported package and granting its tools stay separate Administrator and Policy Author actions.

With `[runtime] sandbox = "podman"` the Connector cannot sandbox the import probe yet and refuses with `SANDBOXED_PROBE_UNAVAILABLE`; build the recipe from `smcpctl catalog import --dry-run` with `smcpctl package build --sandbox podman` there.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `[contextforge] bundled` | `false` | Run the bundled ContextForge instance (FR-22.22). While false, hosted entries are refused with `CONTEXTFORGE_DISABLED` |
| `[contextforge] catalog_file`, `catalog_sha256` | none | Read this catalog instead of the pinned one; both or neither. A wrong digest is reported by `smcpctl catalog status` and the health report's element list, and the Gateway keeps running without a catalog |
| `[contextforge] npm_registry`, `pypi_index` | the public registries | Where a local import fetches the pinned artifact |

## Not built yet

The console view G-15, the bundled ContextForge instance and its lifecycle, hosted-entry import (probe, `manifest_version` 2), per-package isolation, reconciliation, and the hostile fixtures HFC-01 to HFC-14.
