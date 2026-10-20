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

## Importing a hosted entry

With the bundled instance enabled, a hosted entry with auth type `Open` is imported through it (FR-22.9, FR-22.10). The Connector starts the instance if it is stopped, registers the entry as a probe package (team, non-admin user, gateway named `smcp-<entry id>`, virtual server, token scoped to them), reads the served tool list with that token, and removes the probe objects again. It maps each served name `<slug>-<name>` to a manifest name (FR-22.10) and writes a `manifest_version` 2 package (`docs/schemas/manifest.v2.schema.json`): the `upstream` member with the hosted URL, transport, catalog entry and gateway name and slug, every tool with its `backend_name`, `source_trust` `untrusted`, risk class `moderate` or `high`, one egress rule for the hosted host, and as its artifact the canonical JSON of the `upstream` member. The provenance statement adds the instance's image digest, the probe time and the SHA-256 of the hosted server's TLS public key seen by the Gateway (FR-22.11). The trust decision states that the code cannot be inspected and that its operator sees every argument; the Library imports a hosted package only with such a decision, untrusted tools, a moderate or higher risk class and the bundled instance enabled (SR-3-6, `HOSTED_ADMISSION_REFUSED`).

ContextForge v1.0.11 serves a server's tools `get-time` and `get_time` under one name (it turns underscores into hyphens), so such a server is refused with `TOOL_NAME_COLLISION`.

Not built yet: the probe through the entry's E-18 endpoint and the probe secret of API-key entries (they are refused with `HOSTED_IMPORT_UNAVAILABLE`), and the narrowed probe network in the Enforced profile (SR-3.5-2).

## Calling a hosted package

An enabled hosted package is resolved by the Connector when the Gateway launches it (FR-22.29, FR-22.34, FR-22.36). It starts the bundled instance if needed; after each start of the instance it first removes whatever an earlier run left in it. It registers the package with its own team, non-admin user (password generated into the vault as `component.contextforge.user-<slug>`), gateway named as the manifest's `upstream` member, virtual server and one-day token, checks that the virtual server serves exactly the manifest's backend names, and runs the scope self-check over every registered hosted package; a finding suspends every hosted package with `CONTEXTFORGE_SCOPE_BROKEN` and stops the instance. The Tool Dispatcher then reaches the package's virtual server over loopback with the southbound Streamable HTTP transport, authenticated with the package token, which only the Connector holds and hands to the transport at launch. Each call goes out under the tool's `backend_name`; the served list comes back under manifest names, so the usual drift check applies; an `Unknown tool` answer for a manifest tool becomes `-31007` `BACKEND_ERROR` with `backendCode` `-32601` and starts a reconciliation at once. Reconciliation runs every 5 minutes, journals each finding as a `contextforge_drift` event and suspends a drifted revision (`CONTEXTFORGE_DRIFT`).

Not built yet for hosted calls: token renewal before the 24-hour expiry (a Gateway restart renews it), the evidence fields of FR-22.39, and the E-18 endpoint per package (FR-22.40).

## Choosing the bundled instance at setup

`smcpctl bootstrap` and `smcpctl install` ask on a terminal whether to enable the bundled ContextForge instance, with what it adds and its risk, and the default is no (FR-22.44). `--with-contextforge` answers yes without asking; without a terminal and without the flag the answer is no. The answer is written as `[contextforge] bundled`. A yes also fetches the pinned image for this machine when Podman or Docker is installed; a no fetches nothing (FR-22.22). The desktop application's first-run setup is not wired to this choice yet.

## The bundled instance

With `[contextforge] bundled = true` and a Secret Vault (`[secrets]`), the Connector runs the bundled ContextForge instance on demand (FR-22.23): it starts it while a hosted package revision is enabled or a hosted probe runs, and stops it 30 seconds after the last of them ends. An Operator's `smcpctl contextforge start` (or the control API) also keeps it running until `smcpctl contextforge stop`. `smcpctl contextforge uninstall` (Administrator) stops it, removes its data volume and image, retires its credentials in the vault and suspends every enabled hosted package revision; the journal and the hosted packages' Library records stay (FR-22.32).

- **Verification (FR-22.19, SR-3.2-2).** Before the first start and after an image change, the Gateway runs `cosign verify` and `cosign verify-attestation --type spdxjson` on the image index of the release lock for its signer identity (the `docker-multiplatform.yml` workflow at the release tag), pulls the platform image by digest and checks that the local copy carries that digest. The result is kept in `<state>/contextforge/verified.json`; later starts check only the local digest. The verified source-to-image binding is a journal event (`contextforge`, outcome `image_verified`). A failure is `CONTEXTFORGE_UNVERIFIED`.
- **Configuration (FR-22.27, FR-22.37).** Generated, never edited: the admin UI, catalog, plugins, LLM chat, A2A, reverse proxy, WebSocket relay, direct proxy, MCP Apps, stdio transport, bulk import, tool preview, gRPC, elicitation, public registration, every SSO provider, observability and every OpenTelemetry exporter, SMTP, DCR, password reset and CORS are off; email authentication, `AUTH_REQUIRED`, `REQUIRE_JTI`, `REQUIRE_TOKEN_EXPIRATION` and SSRF protection are on; one gunicorn worker, separator `-`, no allowed origin, an SSRF allowlist that holds only E-18 endpoint networks (none yet), and tool timeout, rate and concurrency limits twice the Gateway's CP-13, CP-11 and CP-10. A start whose configuration differs is refused with `CONTEXTFORGE_CONFIG_REFUSED` naming the key.
- **Credentials (FR-22.28).** `JWT_SECRET_KEY`, `AUTH_ENCRYPTION_SECRET`, `BASIC_AUTH_PASSWORD`, `PLATFORM_ADMIN_PASSWORD` and `DEFAULT_USER_PASSWORD` are generated (256 random bits each) into the vault as `component.contextforge.*` entries, delivered only to the Connector by the Secret Broker (a `secret_use` event per start) and passed to the container engine through its environment: never a file, an argument or a log line. The `component.` namespace cannot be created through the vault API or bound to a server. A credential that is empty, a published ContextForge default or shorter than 43 characters stops the start (`CONTEXTFORGE_WEAK_CREDENTIAL`).
- **Container (FR-22.26, FR-22.24 in part).** Podman (preferred) or Docker runs the digest-pinned image with its listener published on `127.0.0.1` on a port chosen at each start, a read-only root filesystem, one private volume for D-16, all capabilities dropped, `no-new-privileges`, 1 GiB memory, 2 CPUs and 256 PIDs. The Enforced-profile parts (rootless Podman under the E-16 profile, the network namespace limited to E-18 endpoints, the firewall rule for the Gateway identity) are not built yet; until then the health report shows `contextforge_unconfined` whenever the instance runs.
- **Health (FR-22.30).** The instance is `starting` until `/health` first answers; with no answer within 60 s it is restarted. While it runs, `/health` is checked every 10 s, and after three failures it is restarted and reported `unhealthy` (`contextforge_unhealthy`), without affecting other servers.

The measured start on macOS arm64 with Docker was 8 to 9 s to the first healthy answer.

## Per-package isolation (built, not yet wired to hosted packages)

`bundle.Admin.Provision` registers one hosted package as the spike found isolating (FR-22.29, FR-22.34): a team created by the administrator, a non-admin user `<slug>@example.com` added as its owner, the gateway (named and slugged as the manifest's `upstream` member) and the virtual server created with team visibility in that team, the administrator then removed from the team, and a token minted by the user for that team with the virtual server as `scope.server_id`, valid one day. `bundle.Admin.SelfCheck` then probes, with each package's token, `tools/list` on `/mcp` and `/rpc`, `tools/call` of another package's tool through its `/servers/<id>/mcp`, `/mcp` and `/rpc`, a GET of its `/servers/<id>/sse`, and two admin routes; anything not refused is a finding, reported with `CONTEXTFORGE_SCOPE_BROKEN`. Against v1.0.11 with two fixture servers the isolated set-up gives no finding and its fixtures see no call; an administrator-owned token restricted only by `scope.server_id` with a gateway outside any team gives findings on `/mcp` and `/rpc`, as the spike reported. The per-package user passwords are generated like the instance credentials; ContextForge refuses passwords with three sequential characters, so such draws are redrawn, and its 90-day password expiry is set out of reach for these machine accounts.

## Reconciliation (built, not yet scheduled)

`bundle.Admin.Reconcile` compares the instance's admin state with the hosted packages the Connector registered (FR-22.33, FR-22.38). It deletes every gateway, virtual server, user, team, prompt, resource, A2A agent and gateway-less tool the Connector did not create, and reports drift of the registered objects without repairing it: a gateway whose name, slug, URL, team or visibility changed, a virtual server whose team or visibility changed, a tool that is no longer served, a tool served but not in the manifest, a changed description, and tools outside the package's team. Against v1.0.11, an injected gateway, user, team and prompt are removed in one pass, and a rename of a package's gateway is reported as name and slug drift with every tool renamed (HFC-08, HFC-13). Running it at each start and every 5 minutes, suspending drifted revisions and the immediate reconciliation after an `Unknown tool` answer come with hosted packages.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `[contextforge] bundled` | `false` | Run the bundled ContextForge instance (FR-22.22). While false, hosted entries are refused with `CONTEXTFORGE_DISABLED` |
| `[contextforge] catalog_file`, `catalog_sha256` | none | Read this catalog instead of the pinned one; both or neither. A wrong digest is reported by `smcpctl catalog status` and the health report's element list, and the Gateway keeps running without a catalog |
| `[contextforge] npm_registry`, `pypi_index` | the public registries | Where a local import fetches the pinned artifact |
| `[contextforge] engine`, `cosign` | from `PATH` (podman before docker) | Absolute paths of the container engine and of cosign |

## Not built yet

- For hosted calls: token renewal, the evidence fields of FR-22.39.
- An E-18 endpoint per hosted package (FR-22.40), the probe secret of API-key entries, and the narrowed probe network (SR-3.5-2).
- The Enforced-profile containment of the bundled instance (rootless Podman under E-16, network namespace limited to E-18 endpoints, firewall rule for the Gateway identity; FR-22.24, FR-22.26, SR-4.5-4, SR-4.7-3).
- The managed-process form for hosts without a container engine (FR-22.20, needs a hashed wheel set in the release lock), upgrade with rollback (FR-22.31), the release lock's signature and the SBOM records (FR-22.18, FR-22.21), and the desktop setup choice (FR-22.44).
- The hostile rows that need the items above (HFC-01, HFC-05, HFC-08 to HFC-13).
