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
| `APPROVAL_DENIED` | `-31001` | An approver denied the call | None; the decision is recorded with the approver's identity |
| `TAINT_DENIED` | `-31001` | The session has read untrusted content and the template denies writing or external tools | Start a new session, or change the template's `taint_action` to `approve` |
| `APPROVAL_REQUIRED` | `-31002` | The call needs a person's approval | Open `data.approvalUrl` or run `smcpctl approvals list`, approve, then repeat the same request |
| `TAINT_APPROVAL` | `-31002` | Approval required because the session has read untrusted content | As `APPROVAL_REQUIRED` |
| `FILTER_BLOCKED` | `-31003` | A required response filter blocked the result | Look up the correlation ID; the filter finding names the rule and rule-set version |
| `SECRET_LEAK` | `-31003` | The result appeared to contain a registered secret | Review the server; the secret grant is suspended until you re-enable it |
| `RESULT_TOO_LARGE` | `-31003` | The result exceeded the size bound (CP-08) | Narrow the request, or raise the bound if the result is legitimate |
| `RELEASE_REFUSED` | `-31003` | The session, policy or stop state changed while the tool ran | Repeat the request |
| `FAIL_CLOSED` | `-31004` | A critical health check failed | Run `smcpctl health`; fix the listed cause (policy snapshot, journal, vault, clock, trust anchors, audit capacity) |
| `EMERGENCY_STOP` | `-31004` | An emergency stop is in effect | An Administrator resumes with `smcpctl resume` or from G-01 |
| `NO_SNAPSHOT` | `-31004` | No verified policy revision is loaded | Check the policy file's signature and schema with `smcpctl config validate` |
| `JOURNAL_UNAVAILABLE` | `-31004` | The decision could not be recorded in the evidence journal | Check disk space and permissions of the journal directory |
| `POLICY_REVISION_CHANGED` | `-31004` | The policy changed between decision and launch | Repeat the request |
| `CAPABILITY` | `-31004` | The one-use launch capability was missing or already used | Repeat the request; if it repeats, report the correlation ID |
| `RATE_LIMITED` | `-31005` | A per-principal or per-template rate limit was reached | Wait; `data.callsPerMinute` shows the limit |
| `QUEUE_FULL` | `-31005` | The dispatch queue is full | Wait, or raise the concurrency limits (CP-10) |
| `SESSION_INVALID` | `-31006` | Missing, expired or unknown token | Sign in again; the harness normally does this itself after a 401 |
| `SESSION_STATE` | `-31006` | The session is suspended or terminated | Sign in again |
| `BACKEND_ERROR` | `-31007` | The server returned a protocol error | `data.backendCode` is the server's code; check the server's stderr in the diagnostic log |
| `DISPATCH_FAILED` | `-31007` | The server could not be started or reached | Check the Servers view (G-10) and the diagnostic log |
| `CLIENT_DEADLINE` | `-31008` | The call did not finish within the client deadline (CP-13) | Repeat with a smaller request, or raise the deadline |
| `UPSTREAM_TIMEOUT` | `-31009` | The server stopped responding; it may have acted | Check whether the action happened before repeating it. The first slice (commit a3193a5) returns `-31008` for this reason code; SRS Appendix B specifies `-31009` |
| `INPUT_REQUIRED_UNSUPPORTED` | `-31010` | The server asked for client input that is not relayed | Enable the MRTR Relay Profile only if you need it |
| `SCHEMA_INVALID` | `-32602` | Arguments do not match the tool's input schema | `data.findings` lists the violations |

## Reason codes seen by operators only

These appear in the evidence journal, the diagnostic log or command output, not in harness errors.

| Reason code | Where | Meaning |
|---|---|---|
| `PERMIT` | Journal decision events | The decision permitted the call |
| `SESSION_END` | Journal session events | A session ended (expiry, termination or revocation) |
| `PROFILE_UNCONFINED` | Server enablement | A `high`-risk server cannot be enabled in the Standalone profile (SR-4-1) |
| `REMOTE_BACKEND_UNSUPPORTED` | Package import | The manifest names a network endpoint; remote backends are out of scope (FR-14.4) |
| `metadata_blocked` | Journal event | A tool description matched a blocking metadata rule and the tool is suspended (SR-5.9-2) |
| `refresh_token_reuse` | Journal event | A rotated refresh token was presented again; the session was ended (SR-2.11-4) |
| `upgrade_rolled_back` | Journal event | An upgrade failed its health check and the previous version was restored (FR-13.8) |
