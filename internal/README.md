# internal: architecture map

This directory holds the Gateway's Go packages, one or more per architecture
element of `ArchitectureV2.md`. This file maps packages to elements, names the
extension points (seams) that elements still to be built plug into, and lists
the known residual gaps of what exists.

Rule for parallel work: an element is added by implementing a seam below and
registering it through `app.Options` (or `adminapi.Server.Handle` for control
API routes). It should not need edits to `edge`, `backend` or `session`.
When a seam is missing, add it to `internal/pipeline` with a default that
keeps today's behavior, and test the default.

## Packages

| Package | Elements | What it holds |
|---|---|---|
| `app` | wiring | Builds every component from a validated config; used by `cmd/smcpd` and the end-to-end tests. Seams are passed in `app.Options`. |
| `edge` | E-01, E-02, E-08, E-12 | Harness listener, MCP protocol (Go SDK, stateless), per-session catalogs, the FR-4.3 call pipeline, launch and release authorization under the barrier, emergency stop, policy activation, health. |
| `pipeline` | seams for E-07, E-09, E-11, E-12, E-13, E-15, E-16, E-20 | Interfaces and defaults (see below). Depends only on `policy` and the MCP SDK. |
| `backend` | E-10, E-14, E-15 (part) | Server registry, public names, FIFO concurrency queue, upstream timeout, bounded result reading, capability check before dispatch. |
| `session` | E-03, E-04 | OAuth 2.1 authorization server (Session Approver sign-in), session API, session table with refresh-token rotation and reuse detection, janitor. |
| `authguard` | E-03, E-24 | Per-source rate limit, lockout with backoff, bounded Argon2id, unknown-account dummy verification. |
| `policy` | E-05 (part), E-06 | Schema-validated policy document, compiled snapshot, decisions, rate windows, filter obligations, `Replace` for hot swap. |
| `audit` | E-21 | Signed hash-chained journal with group-committed fsync, crash recovery, external anchor, verifier; `Fanout` with non-blocking observers; `Memory` for tests. |
| `keys` | E-22 (part) | Name-constrained local server CA, listener certificate and rotation, evidence key, operator token, Argon2id. |
| `adminapi` | E-24 (base) | Control API on the loopback admin listener: login, bootstrap redemption, health, stop, resume, policy reload; role seam (`AddAuthenticator`, `HandleRoles`, `HandlePublic`, `ActorOf`, `RoleOf`). |
| `approval` | E-07 | Approval Service: persisted one-use approvals bound per SR-1.18-2, hold mode, CP-17 expiry, `/api/v1/approvals*`, Approver accounts, watch stream, desktop notifier, harness status route. Wired in `cmd/smcpd`. |
| `profile` | E-23 (part), E-16 | Standalone versus enforced profile decision. |
| `config` | all | TOML configuration validated against `config.schema.json`; Appendix A defaults by key presence. |
| `diag` | all | Diagnostic logger (slog). Not evidence; never logs secrets, tokens or arguments. |
| `ids` | all | UUIDv7 identifiers and 256-bit secrets. |
| `reqtest` | FR-12.10 | `Verifies` and `Partial` requirement claims in tests. |
| `e2e` | all | End-to-end tests over TLS with the test binary as a stdio backend. |
| `egress` | E-18 | Egress Broker: per-instance forward proxy and destination endpoints, grants, pinned DNS, reserved-address refusal, limits, evidence, nftables confinement of sandbox namespaces, `/api/v1/egress` routes. See `docs/egress.md`. |

## Call pipeline (FR-4.3)

`edge/pipeline.go` runs, in order: authenticate (`mcpChain`), session check,
fail-closed check, decision (`policy.Decider`), request inspection
(`pipeline.Filters.RunRequest`), approval (`pipeline.Approver`), launch
authorization, dispatch (`backend.Registry.Call`), response inspection
(`pipeline.Filters.RunResponse`), provenance, release authorization.
Request and response scoring (E-31) are not stages yet.

Evidence ordering: `requested`, `dispatched` and `completed` are appended;
`authorized` (the decision intent) is committed with fsync before the
launch capability is issued; `delivered` is committed before the result is
released; every refusal commits its terminal event. If an append or commit
fails the call is refused with `-31004` and reason `AUDIT_UNAVAILABLE`, and the
journal's sticky error fails the whole endpoint closed.

Barrier: launch and release authorization hold `Gateway.gate` for reading;
`Stop`, `Resume` and `ActivatePolicy` hold it for writing.

## Seams and who fills them

| Seam | Interface | Default | Element and future work |
|---|---|---|---|
| Approval | `pipeline.Approver` (`Request(ctx, ApprovalRequest) (ApprovalResult, error)`), `adminapi.Approvals` | `RefuseApprover`: immediate `-31002` with retry text and console link | Filled by `internal/approval` in `cmd/smcpd`. Anomaly (E-31) and taint obligations still need to reach it; the console (G-13) reads `/api/v1/approvals`. |
| Harness routes | `edge.Gateway.HandleSession(pattern, SessionHandler)` | none | Routes on the harness listener for an authenticated session (E-07 uses `/smcp/v1/approvals/{id}`). |
| Control API roles | `adminapi.Authenticator`, `Server.HandleRoles(pattern, h, roles...)` | `Handle` routes are Administrator-only | An element that owns accounts of another Appendix C role registers an Authenticator; its tokens reach only `HandleRoles` routes naming the role. |
| Request filters | `pipeline.RequestFilter`, registered with `Filters.RegisterRequest(f, Registration{Order, Mandatory})` | `schema-validate` (mandatory, order 100) | E-09 agent: `path-canonicalize`, `url-canonicalize`, `size-limit`, `secret-fingerprint`, `injection-detect`, `unicode-control`. Non-mandatory filters run when a policy rule names them in `filters`. |
| Response filters | `pipeline.ResponseFilter`, `Filters.RegisterResponse` | none | E-11 agent. A filter error or an unknown obligation ID refuses the call. |
| Launch | `pipeline.Launcher` (`Launch(ctx, ServerSpec) (Process, error)`, `Confined()`) | `SubprocessLauncher` (unconfined); `InProcessLauncher` for tests | `internal/sandbox.Launcher` (E-15, E-16, E-17): rootless Podman, selected by `[runtime] sandbox = "podman"` in `cmd/smcpd`; see docs/sandbox.md. |
| Manifests | `pipeline.ManifestSource` (`Tools(ctx, spec, live) (ToolSet, error)`) | `LiveManifest`: live `tools/list`, `Verified: false` | E-13/E-14 agent: signed package manifests (minisign), drift check against the live list, `smcpctl package build|sign|verify`. Health reports `unverified_manifests` until then. |
| Secrets | `pipeline.SecretBroker` (`Resolve(ctx, SecretRequest)`) | `NoSecrets`: a server with `secret_env` does not start | E-19/E-20 agent: vault and broker; record each secret use as evidence. |
| Evidence observers | `audit.Observer`, registered through `app.Options.Observers` | none | E-29 collector, E-26 graph mirror, E-27 store. Observers get events after the journal accepted them, on their own goroutine with a bounded queue; a full queue drops and counts (`Fanout.Dropped`). They can never block or fail a call. |
| Control API routes | `adminapi.Server.Handle(pattern, handler)` | health, stop, resume, policy reload, approvals placeholder, login, bootstrap | E-24 agent: console backend routes; the same bearer authentication, origin and JSON content-type rules apply. |
| Launch capability | `pipeline.Capabilities` (issue) and `pipeline.CapabilityChecker` (consume) | one-use ledger shared by edge and backend | Bound to correlation ID, decision ID, policy revision and public tool name (FR-4.13). |
| Profile | `profile.Resolve(mode, launcher, confined, host)` | standalone on macOS or without a confining launcher | E-16 agent supplies the confining launcher; `[profile] mode = "enforced"` refuses to start without one. |
| Egress | `pipeline.EgressAttacher` (`Attach(ctx, EgressRequest) (*EgressAttachment, error)`), `pipeline.EgressAware` (`SetEgress`) | `NoEgress`; with `[egress] enabled` the broker wraps unconfined launchers (advisory proxy variables) | E-16 agent: implement `EgressAware`, call `Attach` with the instance's `EgressNetwork` (network namespace path and a listen address reachable from it) before the server code runs, add `Env` to the instance, `Close` after exit. A failed `Attach` must fail the launch. |

## Elements not yet started

E-17 Runtime Monitor, E-18 Egress Broker, E-19 Secret Vault, E-25 to E-28
Data Server, E-29 to E-32 Observation and Analytics, E-33 Harness Adapter
Kit. E-17 and E-18 attach to the confining launcher; E-25 to E-29 attach as
evidence observers and must not gate enforcement.

## Residual gaps in what exists

- Result size: lines from a backend are bounded while read (CP-08 plus 64 KiB
  of envelope). When the request ID of an oversized response is not within
  the retained prefix, the response is dropped and the call ends at the
  upstream timeout as indeterminate. Nesting depth is not bounded.
- Held calls: a `tools/call` is served by an event-stream SDK handler
  behind a buffering writer (`edge/stream.go`) and re-encoded as JSON when
  it is never held. A tools/call response that carries more than one event
  without being held (for example backend notifications) is sent as an
  event stream.
- Anchor rollback: replacing the anchor with an older signed copy together
  with deleting later segments is not detectable locally; export the anchor
  off the machine (FR-7.14).
- Per-source rate limits see the tunnel endpoint as the source under the
  Remote Access profile; per-account lockout still applies.
- The SDK client caches `tools/list` for `ttlMs`; after a policy change
  clients see the new catalog when their cache expires. Policy activation
  does not yet send `notifications/tools/list_changed` on open listen
  streams.
- FR-1.10 asks for HTTP 404 on unknown methods; the SDK answers HTTP 200
  with `-32601`.
