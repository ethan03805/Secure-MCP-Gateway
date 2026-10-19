# ContextForge integration spike (October 2026)

A de-risking spike for the IBM ContextForge integration that the owner chose for v1.3.0 (SRS FR-22, `srs_build/req8-contextforge.txt`). It answers four questions before implementation starts: can ContextForge run as a loopback-only backend; can `smcpd` mediate calls through it today; what can a catalog import really prove about provenance; which FR-22 requirements need changing. Everything described here was run on 2026-10-18 on macOS arm64 (Docker Desktop, Standalone profile). Nothing in this spike changes a release requirement or ships ContextForge; the FR-22 corrections it proposed were applied to the planned v1.3.0 requirements afterwards (see Requirements to adjust).

The catalog code and `smcpctl catalog` have since left the experimental state; the current behavior is in [ContextForge catalog and connector](contextforge.md).

What this pull request adds:

| Item | Where | Status |
|---|---|---|
| This report | `docs/contextforge-spike.md` | |
| Catalog reader, classifier and dry-run mapper | `internal/contextforge` | Experimental. Tests use a recorded copy of the v1.0.11 catalog; no test uses the network |
| `smcpctl catalog list` and `smcpctl catalog import --dry-run` | `cmd/smcpctl/catalog.go` | Experimental: every call needs `--experimental-contextforge`. `import` without `--dry-run` is refused |
| `smcp-stdio --experimental-upstream URL` | `internal/adapter/upstream.go` | Experimental bridge that lets a command-configured backend reach a Streamable HTTP server (used for the end-to-end run below) |
| Relay fix: an HTTP error whose body is not JSON-RPC becomes a JSON-RPC error | `internal/adapter/relay.go` | Applies to every relay. Before, ContextForge's `403 {"detail":"Access denied"}` was written to the client as a message no request matched, and the call hung until its timeout |

## Versions

| Component | Version and digest |
|---|---|
| ContextForge | v1.0.11 (2026-09-28), image `ghcr.io/ibm/mcp-context-forge:v1.0.11`, index `sha256:e9639c030162d6cb2f9f188600dd69af8091ec62a7ce307d4a74f4d4f86873df`; linux/amd64 `sha256:1d17a59895ee712a7ae883462dfa8f8d598ea4f3ef28eb2439b1a622555e56d4`, linux/arm64 `sha256:c081736abaf4864af4014a743b2a82447a6de64ec4e6881ea12b77aa1a43554f` (also s390x and ppc64le) |
| Signature | cosign keyless, verified: subject `https://github.com/IBM/mcp-context-forge/.github/workflows/docker-multiplatform.yml@refs/tags/v1.0.11`, issuer `https://token.actions.githubusercontent.com`, source commit `077071bbb43599dd5ab9372ebdbb9a8e686a9816`, trigger `workflow_dispatch` |
| Attestations | SPDX SBOM (`https://spdx.dev/Document`, three attestations, about 18 MB) verifies for the same identity. There is no SLSA provenance attestation |
| Catalog | `mcp-catalog.yml` at tag v1.0.11, 80,402 bytes, SHA-256 `f6be59e31f1017487c8c882fa86b2594214e50b7bcf784773a5a4e0651e91daa`, 135 entries |
| Inside the image | Python 3.12.14, FastAPI 0.141.1, SQLAlchemy 2.0.54, SQLite 3.46.1, gunicorn; runs as UID 10001; MCP protocol version 2025-11-25 |
| Servers registered in it | `ghcr.io/ibm/fast-time-server@sha256:51c9f9cfe0240ba6436b366f30a32217c82c04bdcd8fcd0ab98517979f7b61f0` (SSE, on a private Docker network) and the hosted catalog entry `deepwiki` (`https://mcp.deepwiki.com/mcp`) |

## Resources of the bundled container

| Measure | Value |
|---|---|
| Image size | 574 MB unpacked (arm64) |
| Memory, default workers | 2.78 GiB with `GUNICORN_WORKERS=auto` on a 10-CPU host: 16 or more workers of 220 to 260 MB each, 123 processes and threads |
| Memory, one worker | 404 to 414 MiB idle and after calls (`GUNICORN_WORKERS=1`), 10 processes and threads |
| CPU | 0.3 % idle with one worker; about 3 % idle with the default worker count |
| Start to healthy | about 15 s (schema migration and bootstrap on an empty database) |
| Disk (database) | 2.2 to 2.5 MB of SQLite after two gateways, two virtual servers and three tokens |
| Listeners in the container | `0.0.0.0:4444` (HTTP), published only as `127.0.0.1:4444`; Docker's DNS resolver. It also tries Redis on `localhost:6379` and falls back to the database cache when Redis is absent |

The bundled instance has to pin `GUNICORN_WORKERS` (1 or 2). The default sizes itself to the host and costs gigabytes.

## What worked

1. **Loopback-only run.** The container ran with `-p 127.0.0.1:4444:4444`, generated credentials in a 0600 env file, and UI, catalog UI, plugins, LLM chat, A2A, reverse proxy, WebSocket relay, direct proxy, MCP Apps, stdio transport, bulk import, tool preview and observability all switched off. `/health` and `/ready` answer without authentication (they reveal the pod ID and runtime modes). Everything else needs a token, except that `/openapi.json` and `/docs` accept any validly signed JWT.
2. **Admin API.** Under `/v1`: `/v1/gateways` (register an upstream MCP server), `/v1/servers` (virtual servers: a chosen set of tools behind `/servers/<id>/mcp`), `/v1/tools`, `/v1/tokens`, `/v1/teams`, `/v1/auth/email/admin/users`, `/v1/catalog` and `/v1/catalog/<id>/register`. The admin JWT is minted inside the container with `python3 -m mcpgateway.utils.create_jwt_token` (HS256, `iss=mcpgateway`, `aud=mcpgateway-api`, `jti`, `exp`). `POST /v1/catalog/deepwiki/register` registered the hosted entry and found 3 tools.
3. **MCP endpoints.** `/servers/<id>/mcp` (virtual server), `/mcp` (all tools the token's user can see) and `/rpc` are stateless Streamable HTTP: no `Mcp-Session-Id` is issued, `initialize` returns protocol 2025-11-25 with `serverInfo {"name":"mcp-streamable-http","version":""}`, and responses are `application/json`. `/servers/<id>/sse` offers the old SSE transport.
4. **smcpd to ContextForge to server, end to end.** Two command-configured backends ran `smcp-stdio --experimental-upstream http://127.0.0.1:4444/servers/<id>/mcp`, each with its package-scoped ContextForge token delivered by the Secret Broker as an S3 file (`SMCP_UPSTREAM_TOKEN_FILE`). `scripts/itest-client` signed in over OAuth and called through smcpd:

   | Call | Result |
   |---|---|
   | `cft_time_team_get_system_time` (policy permits) | PASS: time from fast-time-server through ContextForge |
   | `cfw_deepwiki_read_wiki_structure` (hosted entry) | PASS: 1,278 bytes from mcp.deepwiki.com through ContextForge |
   | `cfw_deepwiki_ask_wiki_question` (not in the template) | Refused: not in the session catalog |
   | `cft_time_team_convert_time` (rule with `approval: true`) | Held; `smcpctl approvals approve` released it; result returned; `approval` events `requested`, `approved`, `consumed` |
   | Arguments containing an AWS key pattern | Blocked by the request filters: `SECRET_IN_ARGUMENTS` |
   | A prompt-injection string echoed back in the server's error text | Released and tagged: the response filter `injection-marker` recorded 8 findings (instruction-override, role-override, prompt-disclosure, sensitive-file-request) |
   | ContextForge stopped, then restarted | `backend error` while down; the next call after restart succeeded without restarting smcpd (the relay holds no session) |

   `smcpctl journal verify` reported the journal intact. Each call has `call`, `decision`, `filter` (E-09 and E-11) and, where applicable, `approval` and `secret_use` events, all carrying the server revision.
5. **Package-scoped tokens can be isolated, with care.** See the token finding below.

## What broke or needs attention

| Area | Finding | Consequence |
|---|---|---|
| Server-scoped tokens | A token minted with `scope.server_id` for one virtual server is accepted on the global `/mcp` and `/rpc` endpoints. Those are on ContextForge's list of "general endpoints" that a server restriction allows (`middleware/token_scoping.py`). With an admin-owned token, `/mcp` listed and **called the other virtual server's tools**. A per-server URL check alone is not isolation | FR-22.29 as written cannot pass its own self-check. Isolation held only with one non-admin ContextForge user and one team per hosted package, with the gateway, its tools and the virtual server created with `visibility: "team"` in that team, and the token minted for that user with `team_id`. Then `/mcp` showed only the package's own tools, other virtual servers returned 403, and admin routes returned 403 |
| Email authentication | With `EMAIL_AUTH_ENABLED=false` ContextForge creates no admin user (every JWT then fails with "User not found in database"), does not mount the token catalog `/v1/tokens`, and **does not install the token-scoping middleware** (`main.py`) | FR-22.27 lists `EMAIL_AUTH_ENABLED` among the keys to disable. That makes FR-22.29 impossible. Keep email authentication on, with public registration off (the default: `POST /v1/auth/email/register` answers 403) |
| Credentials | Startup refuses a `DEFAULT_USER_PASSWORD` shorter than 12 characters when email authentication is on. Email addresses are validated, so a `.invalid` domain is refused for users created through the API (the platform admin from the environment is not validated) | FR-22.28 must also generate `DEFAULT_USER_PASSWORD`. Use a reserved domain such as `example.com` for the per-package users |
| Team visibility after the fact | Changing a gateway to `visibility: "team"` after registration did not move its existing tools into the team (`teamId` stayed null), and the team user saw no tools | Create each gateway with its final team and visibility; never re-scope it |
| Tool names | Tools are presented as `<gateway-slug>-<original-name>` with hyphens (`fast-time-get-system-time`); the slug follows the gateway name, so renaming a gateway renames every tool. smcpd's public names turn hyphens into underscores (`cft_time_team_get_system_time`), so `a-b` and `a_b` would collide. Appendix J manifests allow only `[A-Za-z0-9_]{1,47}` | A hosted-package manifest cannot hold ContextForge's names as they are. Either give the manifest a mapping (backend name to manifest name), or set `GATEWAY_TOOL_NAME_SEPARATOR=_` and give gateways slug-safe names; the 47-character limit then includes the slug |
| Unknown tool on a virtual server | A call to a tool that is not on the virtual server returns a *result* `{"isError": true, "text": "Unknown tool: ..."}`, while `/rpc` returns error `-32601` | Treat both as "not found" in E-10's error mapping |
| List changes | Virtual servers advertise `tools.listChanged: false` | Drift through ContextForge is only found by polling: the reconciliation of FR-22.33 and the re-read of SR-3.8-2 are required, not optional |
| SSRF settings | Reaching an upstream on a private network needs `SSRF_ALLOWED_NETWORKS` naming it; the defaults in `.env.example` allow localhost and private networks | Consistent with FR-22.27 (allowlist only the E-18 endpoints) |
| Headers | No session ID, no extra headers needed; `Authorization: Bearer` only; `Mcp-Protocol-Version: 2025-11-25` is accepted | The southbound client can be stateless |
| Southbound transport | smcpd has no Streamable HTTP backend (FR-5.28 to FR-5.30 were deferred). The spike bridged through a stdio process (`smcp-stdio --experimental-upstream`) | The owner has brought FR-5.28 to FR-5.30 back into v1.3.0; FR-22.36 depends on them |
| Resources | One worker uses about 410 MiB; the default worker count uses 2.8 GiB | FR-22.24's "CP-24 limits doubled" must be checked against 410 MiB plus headroom; pin the worker count in the generated configuration |
| Relay error bodies | Fixed in this pull request (see the table at the top) | |

## Catalog import feasibility

The recorded v1.0.11 catalog classifies as follows with the FR-22.3 rules (`smcpctl catalog list --experimental-contextforge --catalog <file>`):

| Class | Entries | Notes |
|---|---|---|
| hosted | 45 | 26 with auth type `Open`, 19 with `API Key` |
| local | 4 | `markitdown`, `azure-devops-mcp`, `playwright-mcp`, `office-powerpoint` |
| unsupported | 86 | 75 `OAuth2.1` and 1 `OAuth2.1 & API Key`; 5 name a repo but no install command; 2 an install command but no repo; 3 neither an install command nor an https URL (for example `fast-time-server`, whose URL is `http://localhost:8101/sse`) |

An entry has `id`, `name`, `category`, `url`, `logo_url`, `auth_type`, `provider`, `description`, `requires_api_key`, `tags`, and sometimes `oauth` (69 entries, public discovery metadata), `secure`, `transport` (4), `repo` (11) and `install` (6).

**Provenance the catalog actually gives:** the catalog file's SHA-256 (bound to the release through the signed image and the tag), the entry's canonical digest, its URL, repository home page and install text. **It gives no version, artifact digest, license, signer or source commit for any entry.** Install strings are unpinned runner commands: `npx -y @azure-devops/mcp`, `npx @playwright/mcp@latest`, `uvx --from office-powerpoint-mcp-server ppt_mcp_server`, and the bare `markitdown-mcp` that does not even name its registry. So:

- For local entries the catalog is a pointer. The operator must still supply the exact version and digest (FR-22.6 already says so), the launch argv (the catalog names only a runner), licenses, the dependency lock and the tool classification. `smcpctl catalog import --dry-run` prints a packaging recipe draft (the input of `smcpctl package build`) with these listed under `operator_must_supply`.
- For hosted entries there is no artifact at all: provenance is the endpoint, the probe's `serverInfo` and the TLS key. The dry run prints a `manifest_version` 2 draft with the proposed `upstream` member, risk class `moderate`, every tool `untrusted`, one egress rule for the host on port 443 and, for API-key entries, an S1 secret slot bound to that host. Tools stay empty until the quarantine probe (FR-22.9).

Example:

```sh
smcpctl catalog import --dry-run --experimental-contextforge \
  --catalog mcp-catalog.yml --sha256 f6be59e31f1017487c8c882fa86b2594214e50b7bcf784773a5a4e0651e91daa \
  --release v1.0.11 deepwiki
```

The parser enforces the FR-22.2 bounds (4 MiB, 2,000 entries, 4,096-character strings) and refuses anchors, aliases, explicit tags, merge keys, duplicate keys, several documents and nesting deeper than 16. An alias bomb is refused without expansion. Install strings are only split on spaces; one with shell syntax gets no proposal (HFC-03), and a dist-tag such as `@latest` is never taken as a version (HFC-04). In the table output, control and format characters in catalog text are replaced so a hostile entry cannot drive the terminal.

## Requirements to adjust

The owner's decisions of 2026-10-18 on the questions this spike raised (accept the SEC 3.1/3.2 gap for hosted servers on SR-3-6's terms, Streamable HTTP southbound back in v1.3.0, a Gateway-held OAuth client planned for a later release, bundled ContextForge opt-in) are recorded in the SRS separately. The findings below still needed a requirement change.

**Applied on 2026-10-19** (`srs_build/req8-contextforge.txt`, regenerated SRS): FR-22.27 keeps `EMAIL_AUTH_ENABLED` on, turns `PUBLIC_REGISTRATION_ENABLED` off and pins `GUNICORN_WORKERS=1`, `GATEWAY_TOOL_NAME_SEPARATOR=-` and `SSRF_ALLOWED_NETWORKS`; FR-22.28 adds `DEFAULT_USER_PASSWORD` and the per-package user passwords to the generated vault credentials; FR-22.29 isolates each hosted package with its own non-admin user and team, team visibility set at creation, tokens owned by that user, and a self-check that probes `/mcp`, `/rpc`, other virtual servers (`/mcp` and `/sse`) and an admin route; FR-22.10 records a deterministic, collision-checked mapping from ContextForge's `backend_name` to the manifest name (Appendix J notes it for `manifest_version` 2); FR-22.33 makes polling the drift signal, treats gateway renames and team changes as drift, and maps `Unknown tool` results and `-32601` to `-31007` `BACKEND_ERROR` with an immediate reconciliation; FR-22.34 names the per-package user and team and forbids E-10 the global endpoints; FR-22.30 adds the start window (about 15 s measured, CP-47 wait); FR-22.24 checks the doubled CP-24 budget against about 410 MiB; FR-22.42 states the unauthenticated `/health` and `/ready`; SR-3.8-2 and HFC-08 and HFC-10 follow. FR-22.19 and FR-22.3 needed no change. `ArchitectureV2.md` (E-36, F-109, I-43, scenario 18.11), `docs/security-limitations.md` and `docs/security-review-2026-10.md` (CF-R6) were updated to match.

| Requirement | Problem | Proposed change |
|---|---|---|
| FR-22.27 | Disabling `EMAIL_AUTH_ENABLED` removes the admin user, `/v1/tokens` and token scoping | Keep email authentication enabled with public registration disabled (`PUBLIC_REGISTRATION_ENABLED` false, the default); add `GUNICORN_WORKERS` (1 or 2) and `GATEWAY_TOOL_NAME_SEPARATOR` to the generated configuration |
| FR-22.29 | `scope.server_id` does not restrict `/mcp`, `/rpc` or `/sse`; the stated self-check would always fail | Mint each package token for a dedicated non-admin ContextForge user who is the only member of a per-package team, with the gateway, tools and virtual server created in that team with team visibility; keep the self-check, and add `/mcp` and `/rpc` to what it probes. Optionally refuse non-`/servers/` paths in front of ContextForge |
| FR-22.28 | `DEFAULT_USER_PASSWORD` is also checked at startup | Add it to the generated credentials; the per-package user passwords also go to the vault |
| FR-22.10, Appendix J | ContextForge tool names contain the gateway slug and hyphens; manifests allow `[A-Za-z0-9_]{1,47}` | Define the name mapping for hosted packages (manifest name, ContextForge name) or constrain the separator and slug; state that the 47-character limit counts the slug |
| FR-22.34 | The virtual-server URL is not enough to separate packages (see FR-22.29) | Name the per-package user and team in the registration |
| FR-22.33 | ContextForge advertises no list changes | State that reconciliation polling is the only drift signal for hosted packages |
| FR-22.30 | `/health` is unauthenticated and reveals runtime details | Acceptable on loopback; note it in FR-22.42 |
| FR-22.24 | CP-24 doubled may be below what one worker needs | Check the doubled limits against about 410 MiB of memory |
| FR-22.19 | The image has an SPDX SBOM attestation but no SLSA provenance | Fine as written (it asks for signature and SBOM); do not add a provenance requirement unless ContextForge publishes one |
| FR-22.3 | `fast-time-server`, ContextForge's own sample, is unsupported (no install, loopback URL) | None: correct, it is a test fixture |

No FR-22 requirement looked infeasible apart from FR-22.29 as written. The catalog cannot supply provenance for local entries; FR-22.6 already requires the operator's pin, so that is a fact to explain in G-15, not a requirement problem.

## Security observations

- **Default authentication.** `AUTH_REQUIRED` defaults to true, and v1.0.11 refuses to start with weak or placeholder `JWT_SECRET_KEY`, `AUTH_ENCRYPTION_SECRET` or (with email authentication) `PLATFORM_ADMIN_PASSWORD` and `DEFAULT_USER_PASSWORD`. Earlier releases shipped a default JWT key that allowed forged admin tokens (GHSA-m8rv-5m6m-32ff, GHSA-8pcq-mx48-hjvj, GHSA-5424-f25v-29r8). Admin JWTs are HS256 with the shared secret: anyone who reads `JWT_SECRET_KEY` can mint a platform-admin token offline, so it must live only in the vault (FR-22.28, SR-2.13-5).
- **Exposed ports.** One HTTP listener on 4444, bound to all container interfaces; the host publish decides exposure. The default `HOST=0.0.0.0` in the README examples publishes it on every interface. Unauthenticated: `/health`, `/ready`.
- **Plugins and code execution.** `PLUGINS_ENABLED` and stdio transport were off. Advisories in plugins and sample servers include a RestrictedPython sandbox escape (GHSA-xm98-3vcf-fph7), SSRF in sample servers (GHSA-gv3m-3mvj-w6f2, GHSA-578v-pgw5-36gv) and server-side template injection to RCE in prompt rendering (GHSA-vwf3-4xxj-qg6h). FR-22.37 and FR-22.38 (no plugins, no prompts) avoid those paths.
- **Other 2026 advisories** (all fixed by v1.0.11 according to the advisories): SSRF protection bypass through redirects (GHSA-c7vv-9h9c-fvj4) and DNS TOCTOU (GHSA-9hgc-g3w5-67cm); expired JWT replay within the session auth reuse window (GHSA-hxq2-5h3j-jqjv); team-scoping gaps in OAuth DCR admin endpoints (GHSA-gj7g-7r6g-jc8v, GHSA-w8vq-gj3v-h664), plugin bindings (GHSA-55gx-p285-xw7f), A2A edit (GHSA-qmfj-jjw4-8qrq) and team join (GHSA-rj22-3ww8-gmv4); SQL sanitizer bypass (GHSA-9qxh-fpx5-vxvw). The pattern (many authorization and scoping gaps) supports the design choice that the Gateway's own policy, filters, approvals and journal stay authoritative and that ContextForge is treated as one untrusted containment domain (FR-22.42).
- **Information exposure.** `/v1/version` (authenticated) returns host name, database URL and the effective settings.
- **Outbound.** Registering a catalog entry makes ContextForge connect to it at once to list tools (`register` connected to mcp.deepwiki.com during the API call). In the bundled design that connection must go through the E-18 endpoint (FR-22.9, FR-22.40).

## Recommended implementation order

1. **Southbound Streamable HTTP client in E-10** (FR-5.28 to FR-5.30, now v1.3.0). It replaces the `--experimental-upstream` bridge, maps ContextForge's errors (403 detail bodies, `Unknown tool` results) and carries the package token from the broker.
2. **Spec fixes above** (FR-22.27, FR-22.28, FR-22.29, FR-22.10 name mapping), before code depends on them. Done on 2026-10-19.
3. **Release lock and verification** (FR-22.18, FR-22.19, SR-3.2-2): the digests and signer identity above; cosign verification and SBOM recording in the release workflow.
4. **Catalog reader and `smcpctl catalog`** (FR-22.1 to FR-22.5, FR-22.7, FR-22.16): promote `internal/contextforge` from experimental, read the catalog only from the release lock or an operator-confirmed file, add the control API and G-15.
5. **Local-entry import through packaging** (FR-22.6, FR-22.8, FR-22.11 to FR-22.15): the dry-run recipe becomes input to `smcpctl package build`.
6. **Bundled instance lifecycle, opt-in** (FR-22.20 to FR-22.28, FR-22.30 to FR-22.32): generated configuration, credentials in the vault, worker count, health, start on demand, upgrade and rollback; Enforced profile container (FR-22.24, SR-4.5-4, SR-4.7-3).
7. **Per-package isolation and reconciliation** (FR-22.29, FR-22.33, FR-22.34, FR-22.38): per-package user, team, gateway and virtual server; the self-check including `/mcp` and `/rpc`; drift polling.
8. **Hosted-entry probe and hosted packages** (FR-22.9, FR-22.10, FR-22.40, SR-3-6, SR-3.5-2), then evidence (FR-22.39, SR-6.18-2) and the hostile fixtures HFC-01 to HFC-14 (FR-22.43).

## Reproducing

The spike's scripts are not in the repository (they held generated credentials). In outline:

1. `docker run -d -p 127.0.0.1:4444:4444 --env-file <0600 file with JWT_SECRET_KEY, AUTH_ENCRYPTION_SECRET, BASIC_AUTH_PASSWORD, PLATFORM_ADMIN_PASSWORD, DEFAULT_USER_PASSWORD> -e EMAIL_AUTH_ENABLED=true -e GUNICORN_WORKERS=1 -e MCPGATEWAY_UI_ENABLED=false -e PLUGINS_ENABLED=false ... ghcr.io/ibm/mcp-context-forge@sha256:e9639c03...`
2. Mint an admin JWT inside the container, create a team, a non-admin user, a gateway and a virtual server in that team, and a token for that user with `team_id` and `scope.server_id`.
3. `smcpctl bootstrap`, `smcpctl secrets init`, store the token with `smcpctl secrets set`, bind it as an S3 slot with `file_env = "SMCP_UPSTREAM_TOKEN_FILE"`, and add a `[[server]]` with `command = "smcp-stdio"` and `args = ["--experimental-upstream", "http://127.0.0.1:4444/servers/<id>/mcp"]`.
4. Start `smcpd` and call a tool with any client.

This is a spike configuration: the server is command-configured and unverified (`degraded: unverified_manifests`), and the README's v1 scope statement (remote servers are not backends) still holds for releases.
