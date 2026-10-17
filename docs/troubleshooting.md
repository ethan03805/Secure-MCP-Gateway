# Troubleshooting and reason codes

Every Gateway error returned to a harness carries a JSON-RPC `code`, `data.reasonCode` and `data.correlationId`, plus `data.decisionId` when a policy decision was made. Search the evidence journal or the console's Audit Investigation view (G-14) for the correlation ID to see every event of the call. This guide is required by SRS FR-18.7; Appendix B of the SRS is the normative table, including the plain-language `data.message` text.

## Quick checks

| Symptom | Check |
|---|---|
| The harness shows no Gateway tools | `smcpctl health`; then confirm the session's template grants tools (`policy.json`) and that the server started (diagnostic log) |
| Every call fails with `-31004` | `smcpctl health` lists the causes; see `FAIL_CLOSED` below |
| TLS or certificate errors in the harness | The harness does not trust the Gateway CA; see the client quick start (`docs/clients/README.md`) |
| The browser sign-in page does not open | The harness must support MCP OAuth; otherwise use `smcp-session` or `smcp-stdio` |
| `smcpctl journal verify` fails | Do not edit or delete journal files; keep a copy of the directory and report the message |

## Reason codes returned to the harness

| Reason code | Code | Meaning | What to do |
|---|---|---|---|
| `NO_PERMIT` | `-31001` | No rule of the session's template permits this tool | Grant the tool in the template, publish the policy, and start a new session |
| `NO_TEMPLATE` | `-31001` | The session's template is not in the active policy | Sign in again; the session was created under a template that no longer exists |
| `DENY_RULE` | `-31001` | A deny rule of the session's template covers the tool | Remove or narrow the deny rule and publish; `data.decisiveRules` names it |
| `EVAL_BOUND` | `-31001` | The decision exceeded CP-12 (more than 256 candidate rules for the server, or 500 ms) | Split the template's rules for that server |
| `APPROVAL_DENIED` | `-31001` | An approver denied the call | None; the decision is recorded with the approver's identity |
| `TAINT_DENIED` | `-31001` | The session has read untrusted content and the template denies writing or external tools | Start a new session, or change the template's `taint_action` to `approve` |
| `ARGUMENTS_INVALID` | `-31001` | The arguments are not valid JSON | Fix the client; the harness sent malformed arguments |
| `ARGUMENTS_TOO_LARGE` | `-31001` | The arguments exceed the size-limit filter's bound | Send less data per call, or raise `[filters.size]` `argument_bytes` or `string_bytes` |
| `ARGUMENTS_TOO_DEEP` | `-31001` | The arguments nest deeper than the size-limit filter allows | Raise `[filters.size]` `argument_depth` if the nesting is legitimate |
| `UNICODE_CONTROL` | `-31001` | An argument contains bidirectional, zero-width or tag characters | `data.findings` names the rule; see [filters.md](filters.md) for the permitted contexts |
| `SECRET_IN_ARGUMENTS` | `-31001` | An argument contains a known credential format or a registered secret | The agent tried to send a credential to a tool; check the session's earlier results for how it obtained it |
| `PATH_INVALID` | `-31001` | A path argument uses an encoded separator, NUL, backslash traversal or `~` | Use a plain absolute or root-relative path |
| `PATH_OUTSIDE_ROOTS` | `-31001` | A path argument resolves outside the granted roots | Add the directory to `[filters.paths]` `roots` or `server_roots` if access is intended |
| `URL_INVALID` | `-31001` | A URL argument cannot be parsed or canonicalized | Check the URL; it must be absolute with a host |
| `URL_NOT_ALLOWED` | `-31001` | The URL's scheme or host is not allowed, or it carries user information | Adjust `[filters.urls]` `schemes`, `hosts` or `deny_hosts` |
| `URL_PRIVATE_ADDRESS` | `-31001` | The URL names a loopback, private, link-local or reserved destination | Set `[filters.urls]` `allow_private = true` only if the tool must reach local services |
| `FILTER_UNAVAILABLE` | `-31001` | A policy rule names a filter ID that is not registered | Correct the rule's `filters` list; `smcpctl filters rules` and [filters.md](filters.md) list the IDs |
| `FILTER_ERROR` | `-31001`, `-31003` | A required filter failed (fail closed) | Look up the correlation ID in the journal; the `filter` event names the filter |
| `FILTER_TIMEOUT` | `-31001`, `-31003` | A filter chain exceeded the CP-14 deadline (default 2 s) | Narrow the request, or raise `[filters]` `deadline` |
| `APPROVAL_REQUIRED` | `-31002` | The call needs a person's approval | Open `data.approvalUrl` or run `smcpctl approvals list`, approve, then repeat the same request |
| `TAINT_APPROVAL` | `-31002` | Approval required because the session has read untrusted content | As `APPROVAL_REQUIRED` |
| `APPROVAL_EXPIRED` | `-31002` | The approval expired (CP-17) while the call was held | Repeat the request to ask for a new approval; decide within `approvals.lifetime` |
| `APPROVAL_CONSUMED` | `-31002` | An identical concurrent call used the one-use approval first | Repeat the request |
| `APPROVAL_UNAVAILABLE` | `-31002` | The approval service could not take the request (for example, the journal could not record it) | `smcpctl health`; check the journal directory and the diagnostic log |
| `FILTER_BLOCKED` | `-31003` | A required response filter blocked the result | Look up the correlation ID; the filter finding names the rule and rule-set version |
| `SECRET_LEAK` | `-31003` | The result appeared to contain a registered secret | Review the server; the secret grant is suspended until you re-enable it |
| `RESULT_TOO_LARGE` | `-31003` | The result exceeded the size bound (CP-08) | Narrow the request, or raise the bound if the result is legitimate |
| `RELEASE_REFUSED` | `-31003` | The session, policy or stop state changed while the tool ran | Repeat the request |
| `FAIL_CLOSED` | `-31004` | A critical health check failed | Run `smcpctl health`; fix the listed cause (policy snapshot, journal, vault, clock, trust anchors, audit capacity) |
| `EMERGENCY_STOP` | `-31004` | An emergency stop is in effect | An Administrator resumes with `smcpctl resume` or from G-01 |
| `NO_SNAPSHOT` | `-31004` | No verified policy revision is loaded | If health lists `policy_signature`, a file under `state/policy/` was altered: restore it from a backup and restart, or publish a valid revision with `smcpctl policy publish` |
| `JOURNAL_UNAVAILABLE` | `-31004`, `-31003` | The decision (`-31004`, the call did not run) or the outcome (`-31003`, the call ran and its result was withheld) could not be recorded in the evidence journal | Check disk space and permissions of the journal directory |
| `POLICY_REVISION_CHANGED` | `-31004` | The policy changed between decision and launch | Repeat the request |
| `CAPABILITY` | `-31004` | The one-use launch capability was missing or already used | Repeat the request; if it repeats, report the correlation ID |
| `RATE_LIMITED` | `-31005` | A rate or burst limit was reached (principal, session or session-tool window) | Wait; `data.callsPerMinute` and `data.burst` show the limits |
| `QUOTA_EXHAUSTED` | `-31005` | The session used its `calls_per_session` quota | Start a new session, or raise the quota in the template or rule |
| `QUEUE_FULL` | `-31005` | The dispatch queue is full | Wait, or raise the concurrency limits (CP-10) |
| `LISTEN_LIMIT` | `-31005` | The session already holds `listen_streams_per_session` (CP-20) open `subscriptions/listen` streams | Close a listen stream, or raise the limit |
| `SESSION_INVALID` | `-31006` | Missing, expired or unknown token | Sign in again; the harness normally does this itself after a 401 |
| `SESSION_STATE` | `-31006` | The session is suspended or terminated | Sign in again |
| `BACKEND_ERROR` | `-31007` | The server returned a protocol error | `data.backendCode` is the server's code; check the server's stderr in the diagnostic log |
| `DISPATCH_FAILED` | `-31007` | The server could not be started or reached | Check the Servers view (G-10) and the diagnostic log |
| `CLIENT_DEADLINE` | `-31008` | The call did not finish within the client deadline (CP-13) | Repeat with a smaller request, or raise the deadline |
| `UPSTREAM_TIMEOUT` | `-31009` | The server stopped responding; it may have acted | Check whether the action happened before repeating it |
| `INPUT_REQUIRED_UNSUPPORTED` | `-31010` | The server returned an `InputRequiredResult` (elicitation, sampling or roots); the Gateway does not relay such requests | The MRTR Relay Profile is not implemented; use a tool that does not ask the client for input |
| `SCHEMA_INVALID` | `-32602` | Arguments do not match the tool's input schema | `data.findings` lists the violations |

## Reason codes seen by operators only

These appear in the evidence journal, the diagnostic log or command output, not in harness errors.

| Reason code | Where | Meaning |
|---|---|---|
| `PERMIT` | Journal decision events | The decision permitted the call |
| `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`, `APPROVAL_EXPIRED`, `APPROVAL_CONSUMED` | Journal `approval` events (E-07) | Lifecycle of a tool-call approval; see `docs/approvals.md` |
| `APPROVER_SIGNIN`, `APPROVER_SIGNIN_FAILED` | Journal events | Approver account sign-in on the control API |
| `ADMIN_ROLE_REFUSED` | Journal `auth_failure` events | An authenticated account's role does not permit the control API route (control API 403 `role_refused`) |
| `role_refused`, `not_pending`, `signin_failed`, `audit_unavailable` | Control API error codes | See `docs/api/approvals.md` |
| `POLICY_PUBLISHED`, `POLICY_ROLLED_BACK`, `POLICY_IMPORTED`, `POLICY_ACTIVATED` | Journal admin events | A policy revision was stored or activated; see `docs/policy-reference.md` |
| `POLICY_INVALID`, `POLICY_CONFLICT`, `POLICY_ACTIVATION_FAILED` | Journal admin events, control API | A publication was refused |
| `POLICY_SIGNATURE` | Journal admin event, health cause `policy_signature` | The active policy revision did not verify at start; the Gateway is fail-closed |
| `POLICY_SIMULATED` | Journal admin events | A policy simulation ran |
| `SESSION_END` | Journal session events | A session ended (expiry, termination or revocation) |
| `PROFILE_UNCONFINED` | Server enablement | A `high`-risk server cannot be enabled in the Standalone profile (SR-4-1) |
| `REMOTE_BACKEND_UNSUPPORTED` | Package import | The manifest names a network endpoint; remote backends are out of scope (FR-14.4) |
| `metadata_blocked` | Journal event | A tool description matched a blocking metadata rule and the tool is suspended (SR-5.9-2) |
| `METADATA_BLOCKED` | Journal `server` event with outcome `metadata_blocked` | Reason code of that event; `detail.findings` names each rule, rule set and version, and `detail.stage` is `import` or `presentation` |
| `REDACTED` | Journal `filter` event | A filter removed or replaced content; the result's provenance disposition is `redact` |
| `refresh_token_reuse` | Journal event | A rotated refresh token was presented again; the session was ended (SR-2.11-4) |
| `upgrade_rolled_back` | Journal event | An upgrade failed its health check and the previous version was restored (FR-13.8) |
| `MEMORY_LIMIT` | Journal `runtime` event | A sandboxed instance reached its memory limit and was killed ([sandbox](sandbox.md)) |
| `PIDS_LIMIT` | Journal `runtime` event | A sandboxed instance reached its PID limit and was killed |
| `UNDECLARED_PROCESS` | Journal `runtime` event | A sandboxed server without `allow_spawn` started a process |
| `EXEC_INTO_INSTANCE` | Journal `runtime` event | Someone ran `podman exec` in a server's container |
| `OPERATOR_KILL` | Journal `runtime` event | An administrator killed an instance with `smcpctl runtime kill` |
| `INSTANCE_EXITED_UNEXPECTEDLY` | Journal `runtime` event | A server instance ended without being asked to; its tools fail until the Gateway restarts |
| `MONITOR_UNAVAILABLE` | Journal `runtime` event | The Runtime Monitor could not find an instance's cgroup |
| `HEALTH_FAIL_CLOSED`, `HEALTH_DEGRADED`, `HEALTH_HEALTHY` | Journal `health` events | The health monitor changed state; the detail lists the causes (`docs/operations/health.md`) |
| `HEALTH_ACK` | Journal event | An administrator acknowledged a latched integrity cause |
| `CONFIG_RELOADED`, `CONFIG_INVALID` | Journal event, `smcpctl reload` | A configuration reload was applied or rejected (`docs/operations/logging-metrics-reload.md`) |
| `LISTENER_CERT_ROTATED`, `LISTENER_CERT_RENEWED`, `SERVER_CA_ROTATION_STARTED`, `SERVER_CA_ACTIVATED`, `EVIDENCE_KEY_ROTATED` | Journal `key_rotated` events | A certificate or key was rotated (`docs/operations/keys.md`) |
| `BACKUP_WRITTEN`, `BACKUP_FAILED`, `BACKUP_DRAIN_TIMEOUT`, `BACKUP_UNENCRYPTED_REFUSED` | Journal event, `smcpctl backup` | Result of a backup request (`docs/operations/backup.md`) |
