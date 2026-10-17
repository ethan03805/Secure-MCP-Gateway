# Health & Safety Monitor

The Health & Safety Monitor (E-23, `internal/health`) evaluates its checks once per second and reports one of three states with the list of active causes (FR-7.11, FR-7.12):

| State | Meaning | Effect on calls |
|---|---|---|
| `healthy` | No cause is active | None |
| `degraded` | Only non-critical causes are active | None; calls proceed |
| `fail-closed` | A critical cause is latched | Every MCP request and every launch authorization is refused with `-31004` and reason `FAIL_CLOSED` |

An emergency stop (`smcpctl stop`) also makes the reported state `fail-closed`; it is handled by the enforcement edge, not by the monitor, and is lifted only by `smcpctl resume`.

## Causes

| Cause | Critical | Integrity | Raised when |
|---|---|---|---|
| `no_decision_snapshot` | yes | no | No policy decision snapshot is loaded |
| `evidence_unavailable` | yes | yes | The evidence journal failed a write or fsync, or was found damaged (the journal's error is sticky until restart) |
| `journal_not_writable` | yes | no | A probe file cannot be created, synced and removed in the journal directory (checked every 5 s) |
| `signing_lag` | yes | no | More than 1,000 events are unsigned, or the oldest unsigned event is older than 60 s (CP-27, SR-6.11-1) |
| `audit_capacity` | yes | no | Free space on the journal's file system is below the 256 MiB mandatory-audit reserve, or cannot be measured (SR-7.10-1; checked every 5 s) |
| `clock_unsane` | yes | no | The wall clock jumped more than 2 minutes against the monotonic clock between two evaluations, or reads a year before 2026 |
| `trust_anchor_expired` | yes | no | The server CA or the listener certificate is outside its validity period (checked every 30 s) |
| `trust_anchor_invalid` | yes | yes | The CA bundle or the listener certificate cannot be read, or the listener certificate was not issued by the active CA |
| `check_failed` | yes | no | A check panicked (a defect; the detail names the check) |
| `disk_space_low` | no | | Free space is below 1 GiB |
| `keys_expiring` | no | | The server CA or listener certificate expires within 30 days |
| `backend_unreachable` | no | | A backend server did not answer an MCP ping within 2 s (checked every 10 s); the detail lists the aliases |
| `unconfined` | no | | The Gateway runs in the Standalone profile (FR-13.10) |
| `unverified_manifests` | no | | A server's tool list comes from the live server, not a signed manifest |
| `observer_events_dropped` | no | | An evidence observer (graph mirror, Observation Collector) dropped events since the previous evaluation |
| `evidence_export_failed` | no | | The last evidence export attempt failed (see [backup.md](backup.md)) |
| `storage_quota_journal`, `storage_quota_observation_store` | no | | The store uses 80% or more of its quota (`[evidence] quota_bytes`, CP-26 10 GiB; `[observation] storage_quota_bytes`, 10 GiB); measured every minute. Every report carries each store's level under `quotas` (FR-9.15) |
| `observation_degraded` | no | | The observation path is degraded; the detail names the stage and the trigger (FR-9.12, see [observation.md](../observation.md#degradation)) |

The graph mirror (when `[graph] enabled`) and the Observation Store register their own checks with `health.Monitor.Register`; they report `degraded`, never `fail-closed`. Not yet checked: vault availability (E-19) and the memory degradation stage (E-28).

## Recovery (FR-7.13)

- A critical cause latches as soon as a check reports it.
- The latch is released only after the cause has been clear for 10 consecutive seconds. If it is reported again in that time, the count starts over.
- An integrity cause (`evidence_unavailable`, `trust_anchor_invalid`) also needs an administrator acknowledgment: `smcpctl health ack <cause>` or `POST /api/v1/health/ack`. The acknowledgment can be given before or after the cause clears; it is recorded in the journal. A cause that is raised again after an acknowledgment needs a new one.
- Every change of state is recorded in the evidence journal as a `health` event with reason `HEALTH_HEALTHY`, `HEALTH_DEGRADED` or `HEALTH_FAIL_CLOSED` and the causes.

## Reading the report

```
$ smcpctl health
health: degraded; causes: unconfined, unverified_manifests; release label: not enforced
{ "state": "degraded", "causes": [ ... ], "checked_at": "...", "info": { "profile": "standalone", "release_label": "not enforced", ... }, "gateway": { ... } }
```

Each cause in `causes` has `name`, `critical`, `integrity`, `detail`, `active`, and for latched causes `since`, `cleared_at`, `ack_required` and `acked_by`. `gateway` is the enforcement edge's own report (emergency stop, sessions, servers). With `--require-not-fail-closed` the command exits with status 1 when the state is `fail-closed`.

The harness listener's unauthenticated `GET /healthz` reports `state`, `causes`, `profile`, `release_label` and `version`, and answers HTTP 503 while fail-closed.

## Errors

| Message or code | Meaning |
|---|---|
| `not_latched` (HTTP 409) from `health ack` | The named cause is not latched or is not an integrity cause |
| `-31004` / `FAIL_CLOSED` at the harness | A critical cause is latched; run `smcpctl health` |
