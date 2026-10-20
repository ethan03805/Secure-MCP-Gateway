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

With the bundled instance enabled, a hosted entry is imported through it (FR-22.9, FR-22.10). The Connector starts the instance if it is stopped, opens an egress endpoint of its own for the entry's host ([Hosted egress](#hosted-egress)), registers the entry as a probe package with that endpoint as the gateway's URL (team, non-admin user, gateway named `smcp-<entry id>`, virtual server, token scoped to them), reads the served tool list with that token, and removes the probe objects again. It maps each served name `<slug>-<name>` to a manifest name (FR-22.10) and writes a `manifest_version` 2 package (`docs/schemas/manifest.v2.schema.json`): the `upstream` member with the hosted URL, transport, catalog entry and gateway name and slug, every tool with its `backend_name`, `source_trust` `untrusted`, risk class `moderate` or `high`, one egress rule for the hosted host, and as its artifact the canonical JSON of the `upstream` member. The provenance statement adds the instance's image digest, the probe time and the SHA-256 of the hosted server's TLS public key seen by the Gateway (FR-22.11). The trust decision states that the code cannot be inspected and that its operator sees every argument; the Library imports a hosted package only with such a decision, untrusted tools, a moderate or higher risk class and the bundled instance enabled (SR-3-6, `HOSTED_ADMISSION_REFUSED`).

ContextForge v1.0.11 serves a server's tools `get-time` and `get_time` under one name (it turns underscores into hyphens), so such a server is refused with `TOOL_NAME_COLLISION`.

An entry that needs an API key (`requires_api_key`, or an auth type naming an API key) is imported only with a probe secret: the name of a vault secret the operator created, and the header it goes in (`smcpctl catalog import <id> --probe-secret NAME --probe-header X-Api-Key --probe-template '{secret}'`, or `probe_secret` in the control API; the default header is `Authorization: Bearer {secret}`). Without one the import is refused with `PROBE_SECRET_REQUIRED`. The Secret Broker delivers the value to the Egress Broker of the probe's endpoint, which inserts the header on the probe's requests to the entry's host (S1); the bundled instance never holds it, and a `secret_use` event names the probe, the destination and the secret's reference. The package's manifest declares one secret slot `api_key` with mode `S1` and the entry's host and port as destination (FR-22.15). The probe's provenance names its network as `e18:<host>:<port>` (SR-3.5-2).

## Calling a hosted package

An enabled hosted package is resolved by the Connector when the Gateway launches it (FR-22.29, FR-22.34, FR-22.36). It starts the bundled instance if needed; after each start of the instance it first removes whatever an earlier run left in it. It registers the package with its own team, non-admin user (password generated into the vault as `component.contextforge.user-<slug>`), gateway named as the manifest's `upstream` member, virtual server and one-day token, checks that the virtual server serves exactly the manifest's backend names, and runs the scope self-check over every registered hosted package; a finding suspends every hosted package with `CONTEXTFORGE_SCOPE_BROKEN` and stops the instance. The Tool Dispatcher then reaches the package's virtual server over loopback with the southbound Streamable HTTP transport, authenticated with the package token, which only the Connector holds and hands to the transport at launch. Each call goes out under the tool's `backend_name`; the served list comes back under manifest names, so the usual drift check applies; an `Unknown tool` answer for a manifest tool becomes `-31007` `BACKEND_ERROR` with `backendCode` `-32601` and starts a reconciliation at once. Reconciliation runs every 5 minutes, journals each finding as a `contextforge_drift` event and suspends a drifted revision (`CONTEXTFORGE_DRIFT`).

The gateway of each enabled hosted package is registered with the URL of the package's own egress endpoint, never the hosted URL (FR-22.34, FR-22.40). A Secret Use Policy binding of the package's alias in mode `S1` for the package's host is delivered before the gateway is registered, because ContextForge connects to the hosted server at registration, and stays bound while the package is registered; a grant for another destination is refused with `HOSTED_SECRET_MODE`, and so is a launch with secret files (S2, S3) (FR-22.15).

The package token is bound to the connection as a token source read for each request, never placed in an environment or file (FR-22.36). Package tokens are minted for one day and renewed an hour before they expire: the Connector mints a new token, runs the scope self-check with the new tokens before any is used, switches the connection to the new token and revokes the old one (`contextforge` events `token_renewed`, `token_renewal_failed`); a finding after renewal suspends every hosted package with `CONTEXTFORGE_SCOPE_BROKEN` (FR-22.29).

The events of a call to a hosted package carry a `route` member: `via` `contextforge`, the package server ID and revision, the ContextForge virtual server, and the instance's version and image digest (`managed-process` for the managed process). A local package's events have no `route` (FR-22.39). On the events that record what the instance returned (the `server_asserted` events of its error messages and notifications, the call's `completed` event and a failure the dispatcher reports for its answer) the route also has `evidence` `server_asserted`: the instance's claims are attributed to the hosted package revision and the instance, never repeated as fact (SR-6.18-2).

## Hosted egress

Before the bundled instance starts, the Connector opens the hosted egress listener of an Egress Broker (E-18) where the instance can reach it, and makes that one address the instance's SSRF allowlist (FR-22.27) and, in the Enforced profile, the only destination of its network namespace (FR-22.24). With Podman the instance runs on slirp4netns with host loopback allowed, the listener binds `127.0.0.1` and the instance reaches it at `10.0.2.2`; with Docker on Linux the listener binds the default bridge's gateway address; with Docker Desktop it binds `127.0.0.1` and the instance uses the address of `host.docker.internal`. The broker is built from the `[egress]` table's limits, DNS servers and destination trust, whether or not `[egress] enabled` is true.

Each enabled hosted package, and each hosted-entry probe, gets its own endpoint on that listener: a URL prefix with a random 128-bit key, bound to the hosted URL's host and port, for which the broker originates TLS (FR-22.40). Requests are checked as endpoint operations are: the broker resolves the name itself and refuses loopback, private, link-local, metadata and reserved addresses; redirects are followed only within the endpoint's host, at most three; size, time and rate limits apply; a registered secret in a request is refused; and each operation is a journal event (`egress`) with the package's alias, never the key. A request whose first path segment is not a live key is refused (`EGRESS_NO_GRANT`), so another local process that finds the listener cannot use an endpoint it was not given. The legacy SSE transport's `endpoint` event is rewritten so that messages are posted through the same endpoint; an `endpoint` URL on another host is replaced by a path no endpoint serves. Egress capabilities (SR-5.16-1) are not required on these endpoints, because ContextForge does not pass a per-call header on; the key binds a request to its endpoint instead.

## Choosing the bundled instance at setup

`smcpctl bootstrap` and `smcpctl install` ask on a terminal whether to enable the bundled ContextForge instance, with what it adds and its risk, and the default is no (FR-22.44). `--with-contextforge` answers yes without asking; without a terminal and without the flag the answer is no. The answer is written as `[contextforge] bundled`. A yes also fetches the pinned image for this machine when Podman or Docker is installed; a no fetches nothing (FR-22.22). The desktop application's first-run setup offers the same choice as a checkbox, unchecked by default ([desktop guide](desktop.md#first-run-setup)).

## The bundled instance

With `[contextforge] bundled = true` and a Secret Vault (`[secrets]`), the Connector runs the bundled ContextForge instance on demand (FR-22.23): it starts it while a hosted package revision is enabled or a hosted probe runs, and stops it 30 seconds after the last of them ends. An Operator's `smcpctl contextforge start` (or the control API) also keeps it running until `smcpctl contextforge stop`. `smcpctl contextforge uninstall` (Administrator) stops it, removes its data volume and image, retires its credentials in the vault and suspends every enabled hosted package revision; the journal and the hosted packages' Library records stay (FR-22.32).

- **Verification (FR-22.19, SR-3.2-2).** Before the first start and after an image change, the Gateway runs `cosign verify` and `cosign verify-attestation --type spdxjson` on the image index of the release lock for its signer identity (the `docker-multiplatform.yml` workflow at the release tag), pulls the platform image by digest and checks that the local copy carries that digest. The result is kept in `<state>/contextforge/verified.json`; later starts check only the local digest. The verified source-to-image binding is a journal event (`contextforge`, outcome `image_verified`). A failure is `CONTEXTFORGE_UNVERIFIED`.
- **Configuration (FR-22.27, FR-22.37).** Generated, never edited: the admin UI, catalog, plugins, LLM chat, A2A, reverse proxy, WebSocket relay, direct proxy, MCP Apps, stdio transport, bulk import, tool preview, gRPC, elicitation, public registration, every SSO provider, observability and every OpenTelemetry exporter, SMTP, DCR, password reset and CORS are off; email authentication, `AUTH_REQUIRED`, `REQUIRE_JTI`, `REQUIRE_TOKEN_EXPIRATION` and SSRF protection are on; one gunicorn worker, separator `-`, no allowed origin, an SSRF allowlist that holds only the hosted egress listener's address, and tool timeout, rate and concurrency limits twice the Gateway's CP-13, CP-11 and CP-10. A start whose configuration differs is refused with `CONTEXTFORGE_CONFIG_REFUSED` naming the key.
- **Credentials (FR-22.28).** `JWT_SECRET_KEY`, `AUTH_ENCRYPTION_SECRET`, `BASIC_AUTH_PASSWORD`, `PLATFORM_ADMIN_PASSWORD` and `DEFAULT_USER_PASSWORD` are generated (256 random bits each) into the vault as `component.contextforge.*` entries, delivered only to the Connector by the Secret Broker (a `secret_use` event per start) and passed to the container engine through its environment: never a file, an argument or a log line. The `component.` namespace cannot be created through the vault API or bound to a server. A credential that is empty, a published ContextForge default or shorter than 43 characters stops the start (`CONTEXTFORGE_WEAK_CREDENTIAL`).
- **Container (FR-22.26, FR-22.25).** Podman (preferred) or Docker runs the digest-pinned image with its listener published on `127.0.0.1` on a port chosen at each start, a read-only root filesystem, one private volume for D-16, all capabilities dropped, `no-new-privileges`, 1 GiB memory, 2 CPUs and 256 PIDs. Outside the Enforced profile the health report shows `contextforge_unconfined` whenever the instance runs.
- **Enforced containment (FR-22.24, SR-4.5-4, SR-4.7-3).** In the Enforced profile the instance is a rootless Podman container with the same flags, its own user namespace (`--userns=auto`, so its own host UIDs), on slirp4netns. Podman creates and initializes it; before its process starts the Connector installs an nftables table `smcp_contextforge` in its network namespace that drops every packet except loopback, replies to accepted connections, connections to its own listener and TCP to the hosted egress listener, reads the table back, and only then starts it. Any failure removes the container. The contextforge CI job checks this with `podman inspect` and from inside the instance: the Internet, the slirp4netns DNS, a LAN address of the host and another listener on the host's loopback are unreachable, the hosted egress listener is reachable, writes outside the volume and `setuid` fail, and no engine or bus socket, host process or host disk is visible (`bundle.TestEnforcedImage`, HFC-12). Without Podman the instance is not offered in the Enforced profile. The host firewall rule of FR-22.26 is not built: in rootless Podman the published port is a slirp4netns listener on `127.0.0.1` that another local user can connect to, and a rule on the host needs root.
- **Managed process (FR-22.25).** On Windows, and on a host without a container engine outside the Enforced profile, the instance runs as a child process of the Gateway: `<python> -m uvicorn mcpgateway.main:app --host 127.0.0.1 --port <port chosen at each start> --workers 1`, where `<python>` is `[contextforge] python`, the interpreter of a virtual environment with the pinned ContextForge release installed. Its environment is only the generated configuration, the credentials and, on Windows, `SYSTEMROOT`; its working directory is `<state>/contextforge/instance`, with D-16 in `data`. On Windows it runs in its own Job Object with kill-on-close and the doubled limits (`winsandbox.StartManaged`), and the health monitor reports `contextforge_unconfined` through `winsandbox.ContextForgeUnconfinedCheck` while it runs; elsewhere the Connector reports the same cause. Before a start the Connector checks that the environment holds the pinned release (`CONTEXTFORGE_VERSION_MISMATCH` otherwise). Without `[contextforge] python` a start is refused with `CONTEXTFORGE_PYTHON_REQUIRED`. The wheel set of FR-22.20, each wheel's SHA-256 checked against the release lock, is not built: the operator's environment is not verified beyond the version.
- **Health (FR-22.30).** The instance is `starting` until `/health` first answers; with no answer within 60 s it is restarted. While it runs, `/health` is checked every 10 s, and after three failures it is restarted and reported `unhealthy` (`contextforge_unhealthy`), without affecting other servers.

The measured start on macOS arm64 with Docker was 8 to 9 s to the first healthy answer.

## Per-package isolation

`bundle.Admin.Provision` registers one hosted package as the spike found isolating (FR-22.29, FR-22.34): a team created by the administrator, a non-admin user `<slug>@example.com` added as its owner, the gateway (named and slugged as the manifest's `upstream` member) and the virtual server created with team visibility in that team, the administrator then removed from the team, and a token minted by the user for that team with the virtual server as `scope.server_id`, valid one day. `bundle.Admin.SelfCheck` then probes, with each package's token, `tools/list` on `/mcp` and `/rpc`, `tools/call` of another package's tool through its `/servers/<id>/mcp`, `/mcp` and `/rpc`, a GET of its `/servers/<id>/sse`, and two admin routes; anything not refused is a finding, reported with `CONTEXTFORGE_SCOPE_BROKEN`. Against v1.0.11 with two fixture servers the isolated set-up gives no finding and its fixtures see no call; an administrator-owned token restricted only by `scope.server_id` with a gateway outside any team gives findings on `/mcp` and `/rpc`, as the spike reported. The per-package user passwords are generated like the instance credentials; ContextForge refuses passwords with three sequential characters, so such draws are redrawn, and its 90-day password expiry is set out of reach for these machine accounts.

## Reconciliation

`bundle.Admin.Reconcile` compares the instance's admin state with the hosted packages the Connector registered (FR-22.33, FR-22.38). It deletes every gateway, virtual server, user, team, prompt, resource, A2A agent and gateway-less tool the Connector did not create, and reports drift of the registered objects without repairing it: a gateway whose name, slug, URL, team or visibility changed, a virtual server whose team or visibility changed, a tool that is no longer served, a tool served but not in the manifest, a changed description, and tools outside the package's team. Against v1.0.11, an injected gateway, user, team and prompt are removed in one pass, and a rename of a package's gateway is reported as name and slug drift with every tool renamed (HFC-08, HFC-13). The Connector runs it at each start of the instance and every 5 minutes, suspends drifted revisions, and runs it at once after an `Unknown tool` answer ([Calling a hosted package](#calling-a-hosted-package)).

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `[contextforge] bundled` | `false` | Run the bundled ContextForge instance (FR-22.22). While false, hosted entries are refused with `CONTEXTFORGE_DISABLED` |
| `[contextforge] catalog_file`, `catalog_sha256` | none | Read this catalog instead of the pinned one; both or neither. A wrong digest is reported by `smcpctl catalog status` and the health report's element list, and the Gateway keeps running without a catalog |
| `[contextforge] npm_registry`, `pypi_index` | the public registries | Where a local import fetches the pinned artifact |
| `[contextforge] engine`, `cosign` | from `PATH` (podman before docker) | Absolute paths of the container engine and of cosign |
| `[contextforge] python` | none | Interpreter of the virtual environment with ContextForge installed, for the managed process (Windows, or no container engine) |

## Not built yet

- The host firewall rule of FR-22.26 for the Enforced profile.
- The wheel set of the managed-process form with each wheel's SHA-256 in the release lock (FR-22.20), upgrade with rollback to a second pinned release (FR-22.31), and the release lock's signature and the image and wheel SBOMs (FR-22.18, FR-22.21).
- The hostile rows HFC-09 (the E-11 filtering and session taint of a swapped result through the full pipeline) and HFC-14's refusal by the running instance in the suite (the contextforge job asserts it).
