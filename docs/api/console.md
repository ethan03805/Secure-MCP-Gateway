# Control API: console routes

Routes of the Management Console & Control API (E-24) that the console owns: sessions, servers, the tool catalog and the evidence journal. They are registered by `internal/consoleapi` on the admin listener (CP-03). The operator guide for the console itself is [../console.md](../console.md).

The listener's rules apply to every route: loopback TLS, `Host` must name the admin listener, a foreign `Origin` or a cross-site `Sec-Fetch-Site` is refused with 403 `origin_refused`, and every POST must have `Content-Type: application/json` (bodies up to 64 KiB). Responses carry `Cache-Control: no-store`.

Authentication is a bearer token in the `Authorization` header: the operator token (`<state>/keys/admin.token`) or an administrator session token from `POST /admin/v1/login`. Every route below is Administrator-only. A missing or unknown token gets 401 `unauthenticated` (recorded as `ADMIN_AUTH_FAILED`); an Approver token gets 403 `role_refused` (recorded as `ADMIN_ROLE_REFUSED`).

Errors have the form `{"error": {"code": "<code>", "message": "<text>"}}`.

Times are RFC 3339 in UTC. IDs are UUIDv7 strings.

## Sessions

### GET /api/v1/sessions

Active harness sessions, newest first.

Response 200:

```json
{"sessions": [
  {"id": "01a14737-...", "state": "active", "principal_id": "claude-code-local", "framework": "claude-code", "profile": "dev",
   "client_id": "https://claude.ai/api/mcp/oauth/client-metadata", "template": "read-only", "policy_revision": "r1",
   "purpose": "", "approved_by": "approver", "harness_version": "", "listener": "tls",
   "created_at": "2026-10-17T00:20:01Z", "idle_deadline": "2026-10-17T00:50:01Z", "max_deadline": "2026-10-17T08:20:01Z"}
]}
```

Fields with no value are omitted. `approved_by` is the Session Approver who signed the harness in (FR-2.19); it is absent for sessions created through the session API. `state` is `active`, `suspended`, `terminated` or `expired`; `end_reason` (`IDLE_TIMEOUT`, `MAX_LIFETIME`, `TERMINATED` or `REFRESH_TOKEN_REUSE`) and `ended_at` are set once a session has ended.

### GET /api/v1/sessions/{id}

One session in the same form. Ended sessions stay readable for 10 minutes after they end.

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | No such session, or it ended longer ago than the retention time |

### POST /api/v1/sessions/{id}/terminate

Ends an active session (FR-8.19): its calls in flight are cancelled, its access and refresh tokens stop working and its MCP sessions are closed (FR-2.11). The action is committed to the journal (`class` `admin`, `outcome` `terminate_requested`, `reason_code` `SESSION_TERMINATED_BY_OPERATOR`, `detail.actor`, `detail.reason`) before the session ends; the session end is recorded by E-04 as a `session` event with `reason_code` `TERMINATED`.

Request (`reason` optional, up to 1000 characters):

```json
{"reason": "harness misbehaving"}
```

Response 200: the session, with `state` `terminated`.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Unknown body field or reason too long |
| 404 | `not_found` | No such session |
| 409 | `not_active` | The session has already ended; the body also has `"state": "<current state>"` |
| 503 | `audit_unavailable` | The action could not be recorded; the session was not ended |

### GET /api/v1/sessions/principals

The framework principals, OAuth clients and Session Approver accounts of the configuration. Password and client-secret hashes are never returned.

Response 200:

```json
{"principals": [{"id": "claude-code-local", "framework": "claude-code", "display_name": "Claude Code on this machine", "profile": "dev", "enabled": true, "active_sessions": 1}],
 "clients": [{"client_id": "https://claude.ai/api/mcp/oauth/client-metadata", "principal": "claude-code-local", "confidential": false,
              "redirect_uris": ["http://localhost:*/callback", "http://127.0.0.1:*/callback"]}],
 "session_approvers": [{"username": "approver"}]}
```

## Servers and catalog

### GET /api/v1/servers

Every `[[server]]` of the configuration with its state.

Response 200:

```json
{"servers": [
  {"alias": "ref", "state": "running", "revision": "live-9ecfde7b49bac9b2", "era": "2026-07-28", "verified": false, "manifest_source": "live",
   "tool_count": 4, "command": "/usr/local/bin/smcp-refserver", "args": ["--root", "/home/me/smcp/sandbox"],
   "env_keys": [], "secret_slots": [], "risk_classes": [], "launcher": "subprocess", "confined": false, "oversized_frames": 0}
]}
```

| Field | Meaning |
|---|---|
| `state` | `running` when the registry launched the server, `not_running` otherwise |
| `revision` | Recorded server revision (`live-<hash>` until signed packages exist) |
| `era` | MCP protocol version negotiated with the server |
| `verified`, `manifest_source` | Whether tool definitions come from a verified manifest; `live` means read from the running server |
| `env_keys`, `secret_slots` | Names of the `env` and `secret_env` entries; values are never returned |
| `launcher`, `confined` | Launcher name and whether it confines the instance |
| `oversized_frames` | Messages from the server dropped for exceeding the result bound |

### GET /api/v1/servers/{alias}

```json
{"server": { ...as above... },
 "tools": [{"name": "read_file", "public_name": "ref_read_file", "description": "Read a UTF-8 text file ...", "revision": "live-9ecfde7b49bac9b2/read_file",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}, "annotations": {"readOnlyHint": true}}]}
```

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | No server with this alias is configured |

### GET /api/v1/catalog

The public tools a session is offered, per Session Allow template of the active policy. Query `template=<name>` returns one template.

Response 200:

```json
{"policy_revision": "r1",
 "templates": [
   {"name": "approval-demo", "profiles": ["dev"], "default_for": [],
    "tools": [{"public_name": "ref_read_file", "server": "ref", "tool": "read_file", "rule_id": "demo-approve", "approval": true, "filters": [], "available": true}]}
 ],
 "tools": [ ...every tool of every running server, in the ToolView form above... ]}
```

`available` is false when the policy names a tool that no running server provides; such a grant appears in no session's catalog. `filters` lists the optional filters the rule adds to the mandatory ones.

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | `template` names no template of the active policy |

## Evidence journal

### GET /api/v1/audit/events

Journal events, newest first, one page at a time. Events are read from the journal files, so the result includes events of the open segment.

| Query | Meaning |
|---|---|
| `class`, `phase`, `origin`, `outcome`, `reason_code`, `session_id`, `correlation_id`, `principal_id`, `decision_id` | Exact match |
| `q` | Case-insensitive substring of the event's JSON |
| `since`, `until` | RFC 3339 times; `since` inclusive, `until` exclusive |
| `limit` | Page size, 1 to 1000, default 100 |
| `before` | `event_id` of the last event of the previous page (`next_before` of that response) |

Response 200:

```json
{"events": [{"event_id": "01a14737-...", "time": "2026-10-17T00:17:01.381Z", "class": "admin", "origin": "E-24", "outcome": "signed_in",
             "reason_code": "ADMIN_SIGNIN", "policy_status": "not_evaluated", "detail": {"actor": "admin:admin"}}],
 "next_before": "", "journal_events": 2}
```

`next_before` is empty on the last page. `journal_events` is the number of events in the journal.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Bad `limit`, `since` or `until`, or `before` names no event |
| 503 | `journal_unreadable` | The journal files could not be read |

### GET /api/v1/audit/events/{id}

One event, its 1-based position in the journal, and every event with the same `correlation_id` in journal order (the phases of the call; empty for events without one).

```json
{"event": { ... }, "position": 42, "related": [ { ...requested... }, { ...authorized... }, { ...delivered... } ]}
```

| Status | Code | When |
|---|---|---|
| 404 | `not_found` | No event with this ID |
| 503 | `journal_unreadable` | The journal files could not be read |

### GET /api/v1/audit/export

The matching events, oldest first, as a download (`Content-Disposition: attachment`). Takes the filters of `GET /api/v1/audit/events` (not `limit` or `before`) and `format` = `csv` (default) or `jsonl`.

CSV columns: `event_id`, `time`, `class`, `phase`, `origin`, `correlation_id`, `session_id`, `principal_id`, `decision_id`, `policy_revision`, `server_revision`, `tool_revision`, `outcome`, `reason_code`, `policy_status`, `detail` (JSON). A cell that begins with `=`, `+`, `-` or `@` is prefixed with `'` so that spreadsheets do not evaluate it (SR-6.17-1). JSON Lines has one event object per line.

The export is committed to the journal before any data is sent (`outcome` `exported`, `reason_code` `AUDIT_EXPORTED`, `detail.format`, `detail.events`, `detail.query`).

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | Unknown `format` or a bad filter |
| 413 | `export_too_large` | More than 100,000 events match |
| 503 | `audit_unavailable` | The export could not be recorded |
| 503 | `journal_unreadable` | The journal files could not be read |

### POST /api/v1/audit/verify

Runs the journal verifier (FR-7.5: segment body hashes and signatures, the hash chain, the open segment and the anchor) and records the result (`outcome` `verified` or `failed`, `reason_code` `JOURNAL_VERIFIED` or `JOURNAL_VERIFY_FAILED`). One verification runs at a time. Body `{}`.

Response 200 (also when verification fails):

```json
{"status": "verified", "segments": 3, "events": 2140, "open_segment": "segment-000003.jsonl", "truncated_tail": false,
 "recovered": [], "anchor_segment": 2, "findings": [], "checked_at": "2026-10-17T00:30:00Z", "duration_ms": 41, "checked_by": "admin:admin"}
```

On failure `status` is `failed` and `error` names the first failure, for example `segment-000001.jsonl: body hash mismatch`.

| Status | Code | When |
|---|---|---|
| 503 | `journal_unreadable` | No journal or evidence public key is configured |

### GET /api/v1/audit/verify

The result of the last `POST /api/v1/audit/verify` since `smcpd` started, or `{"status": "not_run", ...}`.

### GET /api/v1/audit/stream

A `text/event-stream` with one `audit` event per evidence event the journal accepts, starting with the comment `: stream open` and sending `: keep-alive` every 15 seconds (FR-8.23). The console uses it as a change signal to refresh the open view. A reader that falls 64 events behind loses events; the journal remains the record.

```
event: audit
data: {"event_id":"01a1...","time":"2026-10-17T00:31:12.004Z","class":"admin","origin":"E-12","outcome":"stopped","reason_code":"EMERGENCY_STOP"}
```

Fields: `event_id`, `time`, `class`, `phase`, `origin`, `outcome`, `reason_code`, `session_id`, `correlation_id`; empty fields are omitted. Event details are not streamed.

## Console page and unknown routes

`GET /` and every other path that is not under `/api/` or `/admin/` returns the console page (no authentication; the page signs in through the API). Files under `/assets/` are content-hashed and cached as immutable. The page and its assets carry:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY
```

A method other than GET or HEAD on a page path gets 405 `method_not_allowed`. A request to an `/api/` or `/admin/` path that no element registered gets 404 `route_not_found` with the message `this Gateway build does not serve <METHOD> <path>`; the console shows such a route as "Not available in this build".
