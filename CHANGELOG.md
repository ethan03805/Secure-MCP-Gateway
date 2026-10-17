# MCP Gateway documentation changelog

## Unreleased — SRS V1.2 draft, architecture V2.3 draft — 2026-10-16

Re-baseline so that the product, built exactly as specified, is a finished and shippable v1. The owner delegated specification decisions to the project team on 2026-10-16 and made the decisions listed first; the rest close the gaps found by a completeness review of V1.1 (cited as `REVIEW` in the SRS). The SRS build reports 558 requirements (385 FR in 19 roots, 173 SR) with no errors or warnings. No snapshot or tag is made; the release process will make one.

### Owner decisions applied

| Decision | Where | Rationale |
|---|---|---|
| Policy authority is the signed, schema-validated revision held by E-05; evidence authority is the signed, hash-chained journal; the decision intent is flushed before the launch capability is issued; the Neo4j graph and DuckDB store are mirrors | ARCH A-9, OD-15, E-05, E-12, E-21, E-25 and E-26 (T0 to T2), D-01, D-05, D-06, §12; SRS SR-1.1-1, SR-1.1-2 (new), SR-1.2-2, SR-1.14-1, SR-1.15-1, SR-6.2-1, SR-6.3-1, SR-6.10-1, SR-6.11-1, SR-6.13-1, SR-7.3-1, SR-7.7-1, SR-7.8-1, FR-3.10, FR-7.11, FR-9, FR-9.16, FR-9.17, FR-12.5, Appendix D | Enforcement must not depend on a JVM database service. Two files on the Gateway host are simpler to protect, back up and verify than a database, and the graph keeps its value for views and research. SEC 1.1, 6.2 and 6.3 name the graph; their SR children now realize the same guarantees on the journal and the Policy Store (Appendix I.1 item 1). |
| Platform profiles: Enforced on Linux with rootless Podman, nftables, cgroup v2 and systemd; Standalone (unconfined) on macOS arm64 and Linux, with health `degraded: unconfined`, high-risk classes refused and the label "not enforced" | ARCH A-8, OD-14; SRS §1.5.1, §1.6, FR-12.3, FR-12.4, FR-13.9, FR-13.10, SR-4-1 (new), SR-4.1-1, SR-4.5-1, SR-4.6-1, SR-4.7-1, SR-4.7-2 (made conditional on the Enforced profile) | The developers' own machines are Macs. The Standalone profile lets them run every non-containment control while making the absence of containment impossible to miss. |
| Operator self-curation with `smcpctl package build`, `sign` and `verify`, minisign signatures, operator key as a scoped trust anchor, reference packages for filesystem, git, fetch and memory; unpinned runtime launches stay refused; the bootstrap example uses a packaged server | ARCH A-1, E-13, F-96, X-02 (now inside the SoI), X-17, OD-1 and OD-7 decided, §18.1; SRS FR-14 (new root), FR-5.2, SR-3-1, SR-3.5-1 (new, replaces the SEC 3.5 disposition), Appendix J, `docs/schemas/manifest.schema.json` | V1.1 assumed an external curation system that does not exist, so no server could be admitted. Packaging from a pinned digest keeps SR-3.6-1 intact. |
| Approvals: hold mode with keep-alives and a bounded fallback to `-31002` with plain-language text and a console link; approve and deny through `smcpctl approvals`, the console and an OS notification; harness sign-in by a Session Approver role | ARCH E-07, F-17, X-14, OD-5 decided, §18.10; SRS FR-1.51, FR-2.19, FR-2.23, FR-3.14, FR-3.19 to FR-3.25, CP-45, Appendix B Table B.2, Appendix C | V1.1 answered every approval-obligated call with an error the person could not act on. Signing in with the Administrator password exposed the strongest credential daily. |
| Cloud agents (Grok Bot, ChatGPT "dots", Meta Muse) through a Remote Access profile: tunnel, OAuth with operator-approved dynamic registration, rate limits and lockout, `smcp-connect`, vendor allowlist guidance; installing inside the vendor VM is not a control | ARCH A-10, X-13, OD-16, §18.9; SRS FR-16 (new root), SR-2.9-3, SR-2.11-2, SR-4.14-1, SR-4.14-2, CP-48, CP-49; the Overlay Profile is retired | These agents cannot reach a loopback address. A tunnel to a dedicated loopback listener makes remote origin a property of the socket and opens no port. |
| Console: React, TypeScript and Vite with hand-built components, dense tables, no gradients, emoji or icon grids, WCAG 2.2 AA, keyboard operable | SRS §3.1 (Mantine removed), FR-8.28 to FR-8.35, `docs/console-style.md` | Owner direction. |
| License Apache-2.0; distribution through GitHub Releases, `install.sh` and a Homebrew tap; remote backends out of scope for v1; secrets in scope | `LICENSE`, `SECURITY.md`; SRS FR-13 (new root), FR-14.4, FR-18.9, §1.3 | Owner direction. |

### Review gaps closed

| Gap | Change |
|---|---|
| C2 install, upgrade, uninstall | FR-13.1 to FR-13.13: signed archives, verifying installer, Homebrew, idempotent install per profile, upgrade with encrypted backup and rollback on failed health, uninstall that keeps evidence unless purged, configuration `schema_version`; CP-46 directory and identity layout per profile, CP-47 |
| C3 profiles | SRS §1.5.1 states each profile's exact behavior; §1.6 platform and distribution matrix |
| C4 harness bypass | FR-15.1 to FR-15.10: lockdown profiles per client (Claude Code managed settings in FR-15.2), `smcpctl doctor`, reversible lockdown, per-client CA trust; SR-4.9-1, SR-4.11-1 and SR-4.13-1 replace the SEC 4.9, 4.11 and 4.13 dispositions; FR-18.2 requires the Security Limitations document, now written |
| C5 approvals end to end | See the owner decision above; FR-3.25 is a recorded real-harness test with Claude Code |
| C7 traceability honesty | FR-12.10 now distinguishes full and partial claims and requires the report to list every requirement, including unverified ones; FR-19.3 and FR-19.4 make the "enforced" label depend on AT-01 to AT-21; SRS §2.6 defines verified, partial, failing and unverified; Appendix M maps the scenarios |
| C8 hostile backends | FR-19.1, FR-19.2 and Appendix L: 27 hostile fixture rows, each with an expected outcome and the profiles it applies to |
| I1 detection filters | FR-4.16 versioned rule sets, FR-4.17 injection findings as tags only, FR-19.5 labelled corpora with published false-positive and false-negative rates |
| I2 metadata scanning | SR-5.9-2 at import, FR-1.52 again before presentation, FR-4.18 optional untrusted-content delimiting |
| I3 session taint | SR-5.13-2 and ARCH F-99: deterministic, restrict-only |
| I4 harness auth | FR-2.18 (allowlisted metadata documents or pre-registration), SR-2.11-3 (no open metadata fetch), FR-2.22 and SR-2.11-4 (refresh rotation and reuse detection), FR-2.16 (sessions resume after restart through refresh tokens), SR-2.11-5 (no misadvertised `client_id_metadata_document_supported`), FR-15.7 (CA trust per client), FR-15.8 (client matrix as an automated regression) |
| I5 console | FR-8.28 to FR-8.35 |
| I6 operations | FR-17.1 to FR-17.9: diagnostic log (D-14) with rotation and content limits, loopback metrics (X-15), encrypted backups including keys and trust anchors (D-15), TLS, CA and evidence-key rotation, configuration reload; CP-50, CP-51 |
| I7 documentation | FR-18.1 to FR-18.9; `docs/` index records which documents exist |
| I8 Parameter Catalog | Chose to produce the file: `docs/parameters.json` holds the 92 parameter IDs that ARCH §10.3 defines, each with all eleven attributes; FR-10.37 names the file and the build checks it. The V1.1 wording implied 250 parameters, but §10.3 uses a sparse ID range, so the count was wrong rather than the catalog incomplete. P-212 now measures the journal flush and P-247 the journal signing lag. |
| I9, I10 scope | Remote backends and tools-only stated in SRS §1.3, README and `docs/README.md` (FR-18.9) |

### Minor corrections

- Bootstrap secrets are never taken from the command line (SR-7.5-2).
- The Origin check exempts the Gateway's own sign-in form (SR-2.9-1).
- `smcp-stdio` names its default transport and trust root (FR-12.13).
- The local CA carries name constraints and a one-year validity, listener certificates 90 days (SR-2.8-4, CP-53).
- SEC 8.1 now has a disposition explaining how draft, quarantine and test map to packaging; SEC 9.4, 9.5, 9.7 and 10.8 dispositions updated for self-curation.
- README and FloorPlan counts now match the build output; FloorPlan no longer describes the code as pending.
- `architecture.md` is described as background rather than as a current design.

### Generator and data files

- `gen.py` recognizes controlled parameters from Appendix A rather than a fixed range, checks FR, SR and CP references in the front matter and appendices, emits Appendices J to M from `appendix2.md`, and fails when `docs/parameters.json`, `docs/schemas/manifest.schema.json` or `docs/status/elements.json` is inconsistent. X-02 is no longer treated as context-only.
- New function IDs stay within two digits (F-96 to F-99); notification, hold, metadata scanning, dynamic registration, diagnostic log, metrics and `smcp-connect` extend existing functions F-17, F-34, F-59, F-61 and F-95, because the site parser and other tools read function IDs as `F-dd`.
- `docs/status/elements.json` records each element's implementation state at commit a3193a5 (17 partial, 16 not started); `docs/flows/` holds seven sequence diagrams with the implementation's current differences.
- E-09 and E-11 filters (`internal/filters`, `docs/filters.md`): every request filter of FR-4.5 and response filter of FR-4.6, the `delimit-untrusted` obligation (FR-4.18), versioned rule sets with SHA-256 digests (FR-4.16) and labelled corpora with measured false-positive and false-negative rates (FR-19.5), the tool metadata scan at import and presentation with cross-server shadowing and schema bounds (SR-5.9-2, FR-1.52), one `filter` journal event per chain run with timing and P-043/P-143 values (FR-4.7), and `smcpctl filters rules|export|scan`. The filter chains now bound each run by CP-14, convert a filter panic into a block, allow one ID on both chains and record findings, tags and the release disposition in provenance.
- Appendix B Table B.2 (and `docs/troubleshooting.md`) gains the reason codes the request filters and the filter chains return: `ARGUMENTS_INVALID`, `ARGUMENTS_TOO_LARGE`, `ARGUMENTS_TOO_DEEP`, `UNICODE_CONTROL`, `SECRET_IN_ARGUMENTS`, `PATH_INVALID`, `PATH_OUTSIDE_ROOTS`, `URL_INVALID`, `URL_NOT_ALLOWED`, `URL_PRIVATE_ADDRESS`, `FILTER_UNAVAILABLE`, `FILTER_ERROR` and `FILTER_TIMEOUT`. FR-1.51 requires every harness-visible reason code to have a table message; these were returned without one.

### Implementation: server sandbox (E-15, E-16, E-17)

- `internal/sandbox`: a confining `pipeline.Launcher` that runs each backend in rootless Podman with a read-only root, all capabilities dropped, no-new-privileges, Podman's default seccomp profile, a distinct user-namespace range per instance, network `none`, CP-24 cgroup limits, tmpfs `/work` and `/tmp`, and only the operator's mount grants (read-only unless granted write). Environment values reach Podman by name, never on its command line. `Confined()` is true, so a capable Linux host resolves to the enforced profile.
- Runtime Monitor: cgroup sampling on an interval and on kernel change notifications, the Podman event stream, `process_created`, `deviation`, `limit_breach`, `instance_killed` and `instance_exited` evidence, and a kill on memory or PID limit breach.
- The launcher implements `pipeline.EgressAware`; a sandboxed server that asks for egress is refused until rootless network-namespace attachment to the Egress Broker is built.
- `[runtime]` configuration table and `[[runtime.server]]` entries; `smcpctl runtime doctor|spec|status|instances|show|kill`; control routes `/api/v1/runtime*`; `sandbox.Doctor` for `smcpctl doctor`; smcpd refuses to start in the enforced profile when a prerequisite is missing, naming each one.
- `packaging/linux/`: idempotent `install-enforced.sh` (identities, subordinate IDs, CP-46 directories, nftables table `inet smcp`, systemd units) and `smcpd.service`. `scripts/ci-integration.sh` gains an enforced-profile run that proves a sandboxed probe server cannot open network sockets or write outside its mount. Documentation: `docs/sandbox.md`, `docs/api/runtime.md`.
### Implementation decisions in the first slice

Made while hardening the Go slice (PR #8). They interpret the SRS where the code had to choose; none removes a requirement.

| Decision | Where | Rationale |
|---|---|---|
| Harness sign-in uses `[[approver]]` Session Approver accounts, and the Administrator account is refused at the authorization endpoint | `internal/session`, `smcp.toml` `[[approver]]`; FR-2.19, FR-2.23 | Follows the owner decision on approvals: the strongest credential is not used for daily sign-in. FR-2.19 still names the Administrator role as able to sign in; the code is stricter, and the SRS text is to be aligned. |
| Policy rules can carry a `filters` list of filter IDs; mandatory filters always run, and an obligation naming an unregistered filter refuses the call | `internal/policy`, `internal/pipeline`; FR-4.5, FR-4.6 | Lets policy select optional request and response filters without code changes, and fails closed when a named filter is missing. |
| `smcpctl policy reload` refuses a changed document that keeps the active revision ID | `internal/edge` `ActivatePolicy`; FR-3.10 | Catalogs and decisions are keyed by revision ID, so two documents under one ID would make evidence ambiguous. |
| New configuration keys: `[admin_listener]`, `[profile]`, `[log]`, `[[approver]]`, `[admin] bootstrap_token_sha256` and `bootstrap_token_expires`, `[[server]] risk_classes` and `secret_env`, `limits.approval_hold` | `internal/config/config.schema.json` | Needed for the separate control API listener, the profile decision, the diagnostic log, bootstrap without a password on the command line, the SR-4-1 high-risk refusal in Standalone, the secret broker seam and approval hold. `approval_hold` (default 60 s) is not yet a controlled parameter in Appendix A. |
| The fsynced journal commit of the `authorized` event is the SR-6.2-1 intent record; SR-6.2-1 stays Partial until the graph mirror (E-26) exists | `internal/edge`, `internal/audit` | Applies the owner decision that the journal is the evidence authority. The intent is on disk before the launch capability is issued. |
| The local CA is name-constrained to loopback names with a 2-year lifetime; the listener certificate lasts 397 days and is reissued at startup within 30 days of expiry | `internal/keys`; SR-2.8-4, CP-53 | Adds the name constraints SR-2.8-4 requires. The lifetimes are still longer than CP-53 (CA 1 year, listener 90 days) and are to be shortened with certificate rotation (FR-17). |

### CI, status data and site

- Required CI jobs `srs`, `go`, `lint`, `site`, `security` and `linux-integration` (PR #5). `tools/reqreport` reports full and partial claims and every unverified requirement (FR-12.10), and merges `docs/status/elements.json` into `status.json`, which CI publishes to the `site-data` branch.
- The website computes its figures at build time from the repository documents and `status.json` (PR #6).
- The integration run bootstraps with password files, signs in as the Session Approver, calls the reference server's tools, and checks that `smcpctl stop` refuses calls and `smcpctl resume` restores them.
- `site/package.json` overrides the postcss copy inside Next 15 to 8.5.28, which fixes GHSA-6g55-p6wh-862q and GHSA-r28c-9q8g-f849; their npm audit allowlist entries are removed.

- E-07 Approval Service (`internal/approval`): persisted one-use approvals bound to session, principal, server, tool and route revisions, canonical argument digest and policy revision; hold mode up to `limits.approval_hold` with keep-alives (progress notifications or SSE comments); `-31001 APPROVAL_DENIED`, `-31002` with `approvalId`, `expiresAt`, `approvalUrl` and the Appendix B message; retry consumption; CP-17 expiry; evidence events for request, approve, deny, expire and consume; `/api/v1/approvals*` control API and `GET /smcp/v1/approvals/{id}` for the harness; `smcpctl approvals list|show|approve|deny|watch`; desktop notifier (`osascript`, `terminal-notifier`, `notify-send` or a command) with no argument values. Docs: `docs/approvals.md`, `docs/api/approvals.md`.
- E-07: the default `limits.approval_hold` is now 120 s and values above 600 s are refused, matching CP-45 (the first slice used 60 s).
- E-07: Approver accounts are a new `[[approvals.account]]` table. Session Approver accounts (`[[approver]]`) cannot decide tool-call approvals, following SRS Appendix C; ARCH E-24 says a Session Approver "may only approve harness sign-ins and tool-call approvals", which conflicts with Appendix C and should be corrected in the architecture.
- E-02: every Gateway error now carries the Appendix B `data.message` (FR-1.51); a `tools/call` is answered as an event stream only while it is held, and as JSON otherwise.
- E-24: control API role seam (`adminapi.Authenticator`, `HandleRoles`, `HandlePublic`); existing `Handle` routes are Administrator-only and refuse other roles with 403 `role_refused`.
### Implementation: Egress Broker (E-18)

- New package `internal/egress`: per-instance forward proxy (HTTP CONNECT without TLS interception, plain HTTP) and per-destination plain-HTTP endpoints with broker-originated TLS (FR-5.36); grants by host, port, method and SNI; broker-side DNS resolution with the dialed IP pinned to the validated address; refusal of loopback, private, link-local, CGNAT, multicast, reserved and cloud-metadata addresses for IPv4 and IPv6 unless the grant names the exact address; redirects re-validated, at most 3; request size, response size, duration, request-rate and byte-rate limits; Cookie, Set-Cookie and `Smcp-Egress-Auth` stripped; public-fetch method profile; an evidence record per operation.
- nftables rules (github.com/google/nftables) installed in a sandbox network namespace so that only the broker's listeners are reachable; `scripts/ci-egress-netns.sh` proves it on a real kernel in the linux-integration job.
- New seam `pipeline.EgressAttacher` (default `NoEgress`) and `pipeline.EgressAware` for the confining launcher; unconfined launchers are wrapped so instances get `HTTP_PROXY`/`HTTPS_PROXY`, documented as advisory in the standalone profile.
- New `[egress]` configuration section and `[[egress.grant]]` tables, control API routes `GET /api/v1/egress`, `/api/v1/egress/grants`, `/api/v1/egress/connections`, and `smcpctl egress status|grants|connections`. Documentation in `docs/egress.md` and `docs/api/egress.md`.
### Policy administration and decision (E-05, E-06)

- Signed Policy Store (D-01, `internal/policystore`): Ed25519 policy-signing key in `keys/policy.key`, revision files named by the SHA-256 of the canonical document and never rewritten, signed `policy/active.json` replaced by temporary file, flush, rename and directory flush. The Gateway imports `[policy] file` as the first revision and afterwards starts from the store; an active revision that does not verify starts it fail-closed with health cause `policy_signature` (SR-1.1-2).
- Publication, rollback, validation, diff, simulation and an effective permission report through `/api/v1/policy*` (`docs/api/policy.md`) and `smcpctl policy validate|diff|simulate|publish|rollback|history|show`; `POST /admin/v1/policy/reload` now publishes the file through the store. Simulation replays recent journal calls or a JSON Lines scenario against the active and candidate revisions; `requested` call events now record server, tool, template, profile and manifest classes for that purpose.
- Activation updates cached session catalogs in place and sends `notifications/tools/list_changed` on open `subscriptions/listen` streams (residual gap closed).
- E-06: deny rules with precedence (`DENY_RULE`, SR-1.4-1), restrict-only session taint with `taint_action` and per-rule `side_effect` and `source_trust` (`TAINT_APPROVAL`, `TAINT_DENIED`, SR-5.13-2), the CP-11 burst (`[limits] principal_call_burst`, default 10), per-session quotas (`calls_per_session`, `QUOTA_EXHAUSTED`), CP-12 evaluation bounds (`EVAL_BOUND`, SR-1.20-1), and denial when the principal's profile no longer lists the session's template (SR-1-2).
- Appendix B gains `DENY_RULE`, `EVAL_BOUND` and `QUOTA_EXHAUSTED`, which the evaluator produces and the table did not list; CP-11 names the burst window and its configuration keys. `docs/policy-reference.md` (FR-18.5) is written.

## SRS V1.1 draft, architecture V2.2 draft — 2026-10-16

Harness interface revised to match what shipping clients can do (`Client-Compatibility-Brief.md`). No snapshot or tag yet; this is a draft for owner review.

- OAuth 2.1 is the baseline framework credential and session mechanism. The access token is the session. New FR-2.17 to FR-2.22; FR-2.2, FR-2.5, SR-2.1-1, SR-2.1-2, SR-2.3-1 and SR-2.11-1 revised; CP-23 and CP-41.
- mTLS becomes the optional mTLS Harness Profile (FR-2.14, SR-2.8-2). The OAuth Profile and Legacy Northbound Profile rows are removed because both are now baseline.
- Both protocol eras are served in the baseline (CP-04, FR-1.16, FR-1.17, FR-1.46, SR-5.1-1, SR-5.3-1).
- Reference adapters enter the system of interest: E-33 Harness Adapter Kit, F-94, F-95, X-12 in the architecture; FR-12.12 `smcp-session`, FR-12.13 `smcp-stdio`, SR-2.3-2 and CP-43 in the SRS; FR-1.48 now requires an X-12 ICD.
- Public tool names limited to 64 characters with `_` as separator (FR-1.26, FR-1.49, CP-42).
- Architecture document-control row V2.2; OD-2 decided; A-2 and X-01 revised; the Section 8.3 sequence-diagram note fixed so it parses.
- Client-facing hints from the brief §4.5: new FR-1.50 sets `anthropic/requiresUserInteraction` on approval-obligated tools; FR-5.22 extended with the property-name drift rule.
- SRS §3.3 risk 1 (Go SDK dual-era service) retired by `spikes/go-sdk-dual-era/`; FR-1.46 reworded to match (no `Mcp-Session-Id` required for 2025-11-25 clients).

## Implementation — first vertical slice — 2026-10-16

First Gateway code: Go module with `smcpd` and `smcpctl`. OAuth 2.1 sessions, policy decisions, session-scoped catalogs, stdio dispatch and a signed evidence journal, on both protocol eras through the MCP Go SDK. 70 requirements are claimed by passing tests; the README lists what the slice leaves out. Implementation changes are recorded here from now on alongside document baselines.

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
