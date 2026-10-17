# Verification gap list

Requirements that no test or record verifies, grouped by primary element (the first E-xx of the requirement's allocation), each with one line on what is missing. Built on 2026-10-16 from the requirement report of `origin/main` at `067ccbc` plus the tests and records added with this file (rebased on `217535b`, which verifies SR-2.6-1 and SR-8.9-1), by reading each requirement against the code. It is a starting point for implementation work, not a substitute for `make status`: regenerate the report before acting on an entry.

Each entry is marked:

- **missing**: the behavior, or a stated part of it, does not exist in the code.
- **unverified**: the behavior appears to exist, but no test or record proves the whole statement yet. These need a test or an inspection record, not new code.
- **external**: the requirement needs an artifact or run outside the source tree (a release, a person, reference hardware).

Parent requirements whose verification is "Review the verification results of every child requirement" (FR-1, FR-2, FR-3, FR-4, FR-5, FR-7, FR-8, FR-11, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17, FR-19) are verified automatically by `tools/reqreport` once all their children are; they are not listed below.

Requirements deferred from release 1.0 (SRS Section 2.7, Appendix N) are not part of the requirement set and are not listed.

Requirements reported as **partial** are not listed one by one. Their claiming tests state, in the comment next to `reqtest.Partial`, which clauses are missing; `build/reqreport.md` lists the claiming tests of each.

## E-01 Harness Interface Endpoint

- FR-1.1 missing: only the TLS listener exists; the optional CP-02 Unix-domain-socket listener is not implemented, and no test enumerates the listening sockets.
- FR-1.41 unverified: closing the SSE response of an in-flight request cancels the request context; no test measures that the dispatcher sees the cancellation within 1 second.
- FR-1.47 missing: UDS Harness Profile (newline-delimited JSON-RPC over the CP-02 socket).
- FR-1.48 missing: no X-01 or X-12 interface control document in the release.
- FR-11.5 external: no p95 overhead measurement for 64 KiB results at eight concurrent calls on reference hardware.
- FR-12.1 external: no release SBOM license check; needs a release artifact.
- FR-12.2 unverified: no test runs the baseline functions with outbound Internet blocked.
- FR-12.8 external: release provenance bundle (commit IDs, digests, recipes, lockfiles, SBOM, notices) not inspected; needs a release.
- SR-2.8-3 missing: UDS harness socket with mode 0660 and the `smcp-harness` group.
- SR-4.14-1 missing: `smcpctl remote enable` installs no nftables rules in the Enforced profile.
- SR-7.11-1 unverified: CP-06 header bounds and CP-07 body bound are applied by `net/http` and the SDK before parsing; there is no per-source connection limit or CP-09 unauthenticated-work limit on the MCP endpoint (missing), and no test sends slow bodies or connection floods.

## E-02 Protocol Mediator

- FR-1.4 missing: a JSON array batch is refused with a plain-text 400 (no `-32600`), and a JSON-RPC response object is accepted with 202 instead of rejected.
- FR-1.5 missing: an unknown notification is refused with a plain-text 400 instead of 202 with an empty body.
- FR-1.6 missing: a `tools/call` carrying `progressToken` is answered with `application/json`; only held calls and `subscriptions/listen` use `text/event-stream`.
- FR-1.7 missing: SSE responses do not set `X-Accel-Buffering: no`.
- FR-1.16 missing (partial claim exists): a 2026-07-28 POST carrying `Last-Event-ID` is refused by the SDK with HTTP 400 instead of the header being ignored.
- FR-1.18 missing (partial claim exists): 401 and 503 responses written before the body is parsed carry `"id": null`; malformed bodies get plain-text SDK errors.
- FR-1.19 unverified: Gateway codes come from Appendix B (`internal/edge/edge.go`) and reserved codes come from the SDK; the verification also needs the conformance-suite log of FR-12.9, which does not exist.
- FR-1.21 missing: no detection of a duplicate in-flight request ID within a session (the SDK runs stateless).
- FR-1.22 missing: invalid UTF-8 inside a JSON string is accepted; truncated JSON gets a plain-text 400 instead of `-32700`.
- FR-1.31 unverified: results are returned after response inspection with transformed `content`, `structuredContent` and `isError`; no test asserts all three members after a transforming filter.
- FR-1.36 missing: no SSE comment keep-alive at the CP-20 interval on idle listen streams (keep-alives exist only for held calls).
- FR-1.37 missing: a listen stream ended by session end or shutdown is closed without the empty `resultType: "complete"` response carrying the subscription ID.
- FR-1.38 missing: `listen_streams_per_session` (CP-20) is parsed but not enforced; excess listen requests are not refused with `-31005`.
- FR-1.44 missing: `traceparent` is neither recorded as an observation attribute nor stripped from southbound requests by explicit code.
- FR-1.45 missing: `io.modelcontextprotocol/clientInfo` is not recorded as a self-asserted observation attribute.
- FR-4.1 missing: no canonical request object with canonicalized arguments, argument digest and receipt time is built for every call; only the Approval Service computes a canonical argument digest.
- FR-4.2 unverified: a UUIDv7 correlation ID is assigned in `mcpChain` and carried on evidence events; no test traces one call through audit, observation and span records (span records do not exist, FR-10.2).
- FR-12.9 missing: no automated conformance suite over `mcp-spec/2026-07-28/schema/examples`.
- FR-18.7 unverified: `docs/troubleshooting.md` exists; no build check fails when an emitted reason code is undocumented.
- SR-5.2-2 missing (partial claim exists): header values with control characters are refused by `net/http` with a plain 400, not with `-32020`.
- SR-5.6-1 unverified (partial claim exists): rejection of resources, prompts, completion, logging and tasks methods and the tools-only capabilities are tested; no test or record shows that no server-initiated request reaches the harness.
- SR-5.11-1 unverified: results are buffered (`heldWriter`) and released after release authorization; no test shows that no backend-derived byte reaches the harness earlier.

## E-03 Identity & Authentication Service

- FR-2.1 missing: principals are configuration entries without display name, enabled state or credential references; no principal registry or G-11 principal management.
- FR-2.15 missing: UDS peer UID plus bearer key authentication.
- SR-2.11-3 missing: Client ID Metadata Documents are never fetched; registered metadata-URL client IDs are accepted without a fetch, so the CP-52 allowlist and limits do not exist.
- SR-2.11-5 unverified: `registration_endpoint` is advertised only with the Remote Access Profile enabled and `client_id_metadata_document_supported` is never advertised; no test covers both settings of both mechanisms (metadata documents cannot be enabled).

## E-04 Session Manager

- FR-2.12 unverified: decisions use the active snapshot and session catalogs are rebuilt on activation; no test asserts the rebind happens before the session's next evaluated request.
- FR-2.13 missing: no baseline context key is computed or stored at session creation from an Observation Policy.
- FR-2.16 missing: sessions are in memory and do not survive a restart, so an unexpired session cannot be resumed with its refresh token after a restart.

## E-05 Policy Administration Service

- FR-3.1 missing: only Framework Profiles and Session Allow Policy Templates exist; Secret Use, Response, Audit Profile, Observation, Anomaly Response and Research Campaign policy objects are not part of the policy document.
- FR-3.3 missing: no named draft workspace derived from a parent revision.
- FR-3.7 missing: no cost estimate for a draft Observation Policy or Research Campaign from 7 days of call rates.
- FR-18.5 missing: `docs/policy-reference.md` exists, but its examples are not validated by the build against the policy schema, and object types that do not exist are not described.
- SR-1-1 missing: publication does not check grants against the manifest capability ceiling.
- SR-1-3 missing: publication does not check a template against the Framework Profiles that may use it.
- SR-1.9-1 missing: no overlap analysis of permits at publication.
- SR-3.13-1 missing: no high-risk class flags on profiles and templates; high-risk grants are not refused at publication.
- SR-6.9-1 missing: retention and capture settings are not part of the policy document, so they are not validated at publication.
- SR-7.3-1 unverified: signature and schema are validated at start and publication and a bad signature fails closed (`policy_signature`); no test covers a broken cross-reference after restart with the matching health cause.
- SR-7.9-1 missing: no revocation epochs exist to carry forward on rollback; server suspensions are not part of a policy rollback.

## E-06 Policy Decision Service

- FR-3.12 missing: obligations cover filters, approval, rate and quota only; audit profile, observation policy, size limit, timeout, egress grants, secret grants and runtime profile obligations are absent.
- FR-11.2 external: no p95 decision latency measurement under the reference workload.
- SR-1.5-1 missing: no principal enabled state or credential expiry or revocation in the decision; server revision enablement is checked at dispatch, not in the decision.
- SR-1.6-1 missing: permits match server alias and tool name, not exact server and tool revision IDs or the MCP method.
- SR-1.7-1 missing: no argument predicates (FR-3.6), so the predicate operator set does not exist.
- SR-1.7-2 missing: no predicates, so missing-attribute handling does not exist.
- SR-1.10-1 missing: one permit rule applies per tool; obligations of several applicable rules are not combined.
- SR-1.11-1 missing: no route objects; the route is the server alias.
- SR-1.12-3 missing: decision records carry no baseline snapshot ID for anomaly obligations.
- SR-1.18-1 missing: approval is required only where a rule sets `approval`; no floor by manifest side-effect class or Appendix F trigger class.
- SR-1.19-1 missing: no `GET /api/v1/decisions/{id}/explanation` route.
- SR-3.10-1 missing: grants name server aliases and tool names, so a newly enabled revision of a granted server is usable without a new grant.

## E-07 Approval Service

- SR-1.18-3 missing: an approval is not re-requested when a request filter transforms action-defining arguments.

## E-08 Access Enforcement Point

- SR-3.12-1 missing: no `gateway-admin` manifest class exists, so such tools are not excluded from catalogs.
- SR-5.7-2 missing: pagination cursors are the SDK's encoding of the last tool name, not HMAC-protected and not bound to session or policy revision (FR-1.24 is partial for the same reason).
- SR-5.18-2 missing: presented tools drop every `icons` entry, including valid PNG or JPEG `data:` URIs up to 64 KiB, which the requirement keeps.

## E-09 Request Inspection Pipeline

- SR-1.8-1 unverified: `schema-validate` blocks arguments that do not match the input schema with reason `SCHEMA_INVALID` (Appendix B's code; the requirement text says `SCHEMA`); validation is against the live tool schema unless a signed manifest is used, and no test pins the manifest source.
- SR-5.12-1 missing: no second decision after a filter transforms action-defining arguments.

## E-10 Tool Dispatcher

- FR-1.39 missing: backend progress is not relayed northbound (Appendix L HF-07 fails).
- FR-1.40 missing: no progress relay, so no CP-21 progress rate bound.
- FR-1.43 unverified: the CP-13 client deadline is applied (`internal/edge/pipeline.go` `ClientDeadline`) and maps to `-31008`; no test sets a client deadline shorter than the upstream timeout.
- FR-5.13 unverified: stdio framing is the SDK's newline-delimited transport behind `frameFilter`; no test asserts single-line UTF-8 messages.
- FR-5.14 unverified: an invalid stdout line fails the call (Appendix L HF-18 passes in the hostile suite, which runs under a build tag and does not claim requirements in the report).
- FR-5.19 unverified: the SDK client sends `initialize` and `notifications/initialized`; the requested version is the SDK's latest, not pinned to 2025-11-25, and capabilities are not empty (see SR-5.6-2).
- FR-5.20 missing: legacy server-initiated requests are answered by the SDK client (for example `roots/list`) instead of `-32601` (Appendix L HF-26 fails).
- FR-5.21 unverified: the complete paged `tools/list` is read at start (`internal/backend/backend.go`, `sess.Tools`); no test pages a backend catalog.
- FR-5.23 missing: no explicit handling of absent or unrecognized `resultType` from backends.
- FR-5.24 missing: an `InputRequiredResult` is not mapped to `-31010` (Appendix L HF-25 fails).
- FR-5.26 missing: cancellation is not propagated southbound with `notifications/cancelled`.
- FR-5.32 missing: the northbound progress token is passed southbound unchanged instead of a Gateway-generated unique token.
- SR-5.6-2 missing: the southbound client is built with nil `ClientOptions.Capabilities`, so the SDK declares its default `roots` capability; passing `&mcp.ClientCapabilities{}` in `internal/backend/backend.go` would remove it.
- SR-7.2-1 missing: a lost response after dispatch is recorded as indeterminate with `-31009` for timeouts, but the side-effect class is not consulted and the slow-drip case fails (Appendix L HF-17).
- SR-7.12-1 missing: northbound cancellation is not propagated southbound.

## E-11 Response Inspection Pipeline

- FR-19.1 unverified: the hostile fixture server and suite exist (`internal/hostile`, build tag `hostile`) and publish results, but the suite does not claim requirements through `reqtest`, and 7 of 27 rows do not pass.
- SR-5.20-1 unverified: the SDK client rejects malformed envelopes and uncorrelated IDs, and `CallToolResult` decoding fails on invalid results; no test returns each malformed case and checks that the result is withheld with evidence.

## E-12 Enforcement Coordinator

- FR-11.10 unverified: `Stop` takes the gate and every later launch authorization is refused; no test measures the 1 second bound under load.
- SR-1.2-2 missing: a failed decision-intent commit refuses the call with reason `AUDIT_UNAVAILABLE`, not `JOURNAL_UNAVAILABLE` (Appendix B); the graph-outage half is covered by the graph mirror being an observer.
- SR-2.4-1 unverified: session termination is visible to the next launch authorization immediately; principal and credential revocation do not exist (missing), and no test runs revocation under load against CP-16.
- SR-4.1-1 external: distinct CP-46 service identities are prepared by `packaging/linux/install-enforced.sh`; running processes on an Enforced host have not been inspected.
- SR-6.3-1 missing: a failed commit of the delivered event refuses with `-31004` (`AUDIT_UNAVAILABLE`), not the `-31003` the verification expects.

## E-13 Library Trust Verifier

- FR-18.6 external: `docs/packaging-guide.md` exists; nobody has followed it to package a non-reference server.
- SR-3-4 missing: no revocation-feed staleness tracking, import blocking or alert.

## E-14 Local Server Registry

- FR-1.49 unverified: enablement refuses public-name collisions (Appendix L HF-14 passes in the hostile suite); no claiming test reports both backend tool names.
- SR-3.11-1 missing: classification overrides do not exist.

## E-15 Server Runtime Manager

- FR-5.10 missing: instances are shared across sessions; per-call and per-session scopes do not exist.
- FR-5.11 missing: no instance reuse by scope and no CP-38 idle teardown.
- FR-5.15 unverified: stderr is kept in a bounded buffer and never forwarded to the harness; no test checks the CP-37 bound and the absence from harness traffic together.

## E-18 Egress Broker

- SR-5.8-2 missing: the Egress Broker does not run the `secret-fingerprint` filter over outbound URLs, headers and bodies.

## E-20 Secret Broker

- SR-2.13-2 missing: delivery buffers are wiped where they are byte slices, but S4 environment delivery and string conversions keep copies that cannot be overwritten.

## E-21 Audit & Evidence Service

- FR-7.3 unverified: `/api/v1/audit/events` filters and pages the journal; no test covers every listed filter and the 500-event page bound.
- FR-7.6 missing: no Audit Profile alert rules, so no console alerts from them.
- SR-6.4-1 missing: events carry decision, policy revision, server and tool revision IDs, but no decisive rule revision IDs (rules are not versioned objects) and no audit profile revision.
- SR-6.5-1 missing: event origins are element IDs (`E-02`, `E-12`), not the `gateway`, `backend`, `broker`, `admin` labels.
- SR-6.6-1 missing: payload capture is directed by `[observation]` configuration, not by an evaluated Audit Profile, Observation Policy or Research Campaign.
- SR-6.8-1 missing: captured payloads are not stored as age-encrypted blobs referenced from the graph.
- SR-6.12-1 external: the evidence key and checkpoint directory permissions depend on the Enforced installation's identities; not exercised.
- SR-6.13-1 unverified: the journal is independent of the graph mirror, and the mirror catches up from the journal; no test stops the graph database during traffic and compares `policy_status` after recovery.
- SR-6.15-1 missing: no purge operation and no deletion receipts.
- SR-6.18-1 missing: stderr, backend error messages and notifications are not recorded as `server_asserted` evidence.
- SR-6.20-1 unverified: the graph mirror projects `FOR_DECISION` links (`internal/graph/project.go`); no claiming test covers both a denied and a permitted call.

## E-22 Key & Trust Anchor Manager

- FR-7.10 unverified: trust anchors are enrolled with `smcpctl trust` and `POST /api/v1/packages/trust` (G-10); no Demonstration record shows the fingerprint confirmation and the stored risk classes and expiry.
- SR-2.2-1 missing: no per-instance credential issuance by E-22 with independent revocation (pre-registered OAuth clients are configuration entries).

## E-24 Management Console & Control API

- FR-2.23 missing: Session Approver accounts are configuration entries; no Administrator flow creates them, and no check that the password differs from the Administrator's.
- FR-8.3 to FR-8.8, FR-8.11 to FR-8.13, FR-8.15 to FR-8.17, FR-8.20, FR-8.21 (G-01 to G-05, G-07 to G-09, G-12, G-13 view requirements) unverified: every view exists and `console/e2e/views.spec.ts` exercises each; the tests' partial claims reach the requirement report (`console/e2e/reqreport.ts`), but no Demonstration record exists. Where a requirement names policy objects that do not exist (FR-3.1: Audit Profile, Observation Policy, Anomaly Response Policy and Research Campaign as published policy objects), that part is missing; the G-03 and G-06 editors produce the `[observation]` configuration table instead.
- FR-8.24 external: the timed first-time-user task has not been run.
- FR-8.25 unverified: views carry a `Help` section (`console/src/ui.tsx`); help for every policy field and catalog parameter has not been inspected.
- FR-8.29 unverified: `console/e2e/views.spec.ts` covers loading, empty and error states with partial claims; no test covers all three states for every view.
- FR-8.30 external: no browser-support matrix run.
- FR-8.31 unverified: G-01 shows a first-run checklist (`console/src/views/Control.tsx`); no record compares its items with the requirement's list.
- FR-8.32, FR-8.33 unverified (partial claims): `console/e2e/a11y.spec.ts` runs axe (WCAG 2.2 AA tags) on every view as it loads and tabs through every control of every view in Chromium and Firefox, checking reachability and focus-indicator contrast; the manual check is recorded in `FR-8.32.md`. Missing: axe on every intermediate state of the acceptance tests (FR-8.32), and completing every action with keyboard events only (FR-8.33).
- FR-8.35 unverified: `docs/console-style.md` holds the checklist; no inspection record against every view.
- FR-11.8 external: no 30-day reference dataset query latency measurement; the journal has no index (E-21 note).
- FR-13.1 external: no GitHub Release has been inspected; the release workflow signs the checksum file with minisign (key in `SECURITY.md`), but the SBOMs are separate release assets, not files inside each archive.
- FR-13.3 external: GoReleaser writes `Formula/smcp.rb` to `ethan03805/homebrew-tap` on release; no release has published it, and no CI job installs from the tap on macOS and Linux and compares digests.
- FR-19.3 missing: no release-labelling step that checks AT-01 to AT-21 results.
- FR-19.4 missing: no AT scenario is claimed by an automated test or a `docs/verification/AT-nn.md` record.
- SR-2.7-1 missing: configuration accepts any `$argon2id$` verifier; one with parameters below CP-28 (64 MiB, t = 3, p = 1) is not refused.
- SR-3.3-1 unverified: React escapes text by default; no test renders HTML or script in manifests and SBOMs, and no 256 KiB per-page bound is enforced.
- SR-7.5-1 unverified: `smcpctl bootstrap` writes a one-use bootstrap credential; no test covers the expired and used cases against the control API.
- SR-7.5-2 missing: password files are read without checking that their mode is 0600 or stricter, and `-` (standard input) is accepted.

## E-25 Graph Database Engine

- FR-9.18 unverified: the migrations create the indexes; the claiming test needs a running Neo4j and does not run in `make status`.
- FR-11.1 missing: no reference workload generator.
- FR-12.5 missing: no declared start ordering of the per-element services (one `smcpd` process); systemd units exist for the Enforced profile only.

## E-26 Data Access Service

- FR-9.4 missing: no priority classes for queued writes.
- FR-9.5 missing: observation records are not batched through the Data Access Service.
- FR-9.6 missing: no P2 backpressure signal.
- SR-6-3 missing: observation data served to the console is filtered by route role only, not by each field's sensitivity class.

## E-28 Data Lifecycle & Memory Manager

- FR-9.12 missing: no memory manager or degradation order.
- FR-9.15 missing: no storage quotas, warnings or quota reporting to E-23.
- FR-11.9 external: idle resident memory not measured.
- FR-12.4 external: CP-46 directories, owners and modes have not been inspected on installed Enforced and Standalone hosts.

## E-29 Observation Collector

- FR-10.2 missing: no per-stage timing spans with CPU time.
- FR-10.9 unverified: meta-metrics are sampled by the collector; no test checks P-240 to P-250 at a 10-second interval.
- FR-10.11 missing: no span-time aggregation by policy revision, rule, filter and Observation Policy.
- FR-11.4 external: collector overhead not measured.

## E-31 Anomaly Scorer

- FR-10.29 unverified: score records carry snapshot, context, per-feature values and z-scores, combined score and band; no inspection record of an abnormal call's record including the resulting actions.

## E-33 Harness adapters

- FR-15.9 missing: no dated manual cloud-agent run is recorded; every cloud entry in `docs/clients/matrix.json` is `not-run`.
- FR-16.10 missing: the cloud-agent quick start states each vendor allowlist setting as "not confirmed" rather than naming the setting or stating that none is offered.
- FR-18.3 external: per-client quick starts exist; none has been followed at the pinned version for every client (two local clients fail on the CA name constraints).
