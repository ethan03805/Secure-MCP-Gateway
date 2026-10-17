# Control API: packages

Routes of the Library Trust Verifier (E-13) and Local Server Registry (E-14) on the control API (admin listener, CP-03). They are registered by `internal/library` through `adminapi.Server.Handle`, so the control API's rules apply: a bearer token (the operator token in `<state>/keys/admin.token` or an administrator session token from `POST /admin/v1/login`), no foreign `Origin` or cross-site `Sec-Fetch-Site`, and `Content-Type: application/json` on every POST (an empty object `{}` when there is no body). A request without a valid token gets `401` and an `auth_failure` evidence event. A successful authentication is the Administrator action that enabling requires (SR-3.9-1).

Errors have the control API's form: `{"error": {"code": "<reason code>", "message": "<text>"}}`. Refusals are `409` with a reason code from the [packaging guide](../packaging-guide.md#reason-codes); an unknown revision is `404` `PACKAGE_UNKNOWN`; a malformed body is `400` `bad_request`.

State changes are recorded as evidence events of class `package` (origin `E-14`, or `E-13` for imports and revocations) with the actor in `detail.actor` and the revision in `server_revision`.

## GET /api/v1/packages

Lists imported revisions, the packaged `[[server]]` entries of this Gateway, and the trust anchors.

```json
{
  "library": "/srv/smcp/state/library",
  "revisions": [
    {
      "server_id": "mcp-filesystem",
      "revision": "2026.8.31",
      "state": "enabled",
      "state_reason": "enabled",
      "state_changed_at": "2026-10-17T00:16:29Z",
      "state_actor": "admin:alice",
      "alias": "fs",
      "risk_class": "moderate",
      "artifact_type": "npm",
      "index_sha256": "…",
      "manifest_sha256": "…",
      "artifact_sha256": "a8d56c56811437ba3fac961b8083387eec0d843c6f6d7f8ca3121b0a04983fca",
      "tree_sha256": "…",
      "tools_sha256": "…",
      "enablement_sha256": "…",
      "signer_key_id": "7B3357B76507695D",
      "anchor": "operator",
      "imported_at": "2026-10-17T00:16:20Z",
      "tools": ["create_directory", "directory_tree", "…"]
    }
  ],
  "servers": [
    {"alias": "fs", "package": "mcp-filesystem", "revision": "2026.8.31", "status": "running"},
    {"alias": "old", "package": "mcp-old", "status": "not_started", "reason_code": "PACKAGE_NOT_ENABLED", "reason": "…"}
  ],
  "trust_anchors": [
    {"name": "operator", "key_id": "7B3357B76507695D", "classes": ["low", "moderate"], "expires": "2027-10-17T00:00:00Z"}
  ]
}
```

`servers[].status` is `starting`, `running`, `suspended` or `not_started`. `expires`, `recuration_due` and `state_actor` appear when set.

## GET /api/v1/packages/{id}/{revision}

One revision with its signed manifest and provenance statement as stored at import.

```json
{
  "revision": { "server_id": "mcp-filesystem", "revision": "2026.8.31", "state": "enabled", "…": "…" },
  "manifest": { "manifest_version": 1, "server": { "id": "mcp-filesystem", "…": "…" }, "tools": [ … ] },
  "provenance": { "provenance_version": 1, "source": { "kind": "registry-tarball", "uri": "…", "sha256": "…" }, "…": "…" }
}
```

The manifest and provenance are untrusted content supplied by the package publisher; a client must render them as escaped text.

## POST /api/v1/packages/{id}/{revision}/enable

Request: `{}` or `{"alias": "fs2"}` (1 to 16 characters of `a-z 0-9`; default the revision's alias).

Response `200`:

```json
{"revision": {"server_id": "mcp-filesystem", "revision": "2026.8.31", "state": "enabled", "alias": "fs2", "enablement_sha256": "…", "…": "…"}, "restart_required": true}
```

`restart_required` is true unless that revision is already running: servers are launched at Gateway start. Refusals: `STATE_TRANSITION_REFUSED` (revoked or retired), `PROFILE_UNCONFINED`, `ALIAS_CONFLICT`, `STATEFUL_UNCONTRACTED`, `MANIFEST_EXPIRED`, `PUBLIC_NAME_COLLISION`.

## POST /api/v1/packages/{id}/{revision}/disable

Request: `{}` or `{"reason": "maintenance"}`. Changes the revision to `verified-disabled`. A running instance of it is torn down at once and its tools leave the catalog.

Response `200`: `{"revision": { … "state": "verified-disabled" … }}`.

## POST /api/v1/packages/{id}/{revision}/retire

Request: `{}` or `{"reason": "replaced by 2026.9.1"}`. Changes the revision to `retired` (final), tears down a running instance, and deletes the cached artifact when no non-retired revision references it (FR-5.39).

Response `200`: `{"revision": { … "state": "retired" … }}`.

## POST /api/v1/packages/scan

Request: `{}`. Scans the library now (FR-5.3): imports new packages, applies revocation entries and suspends expired revisions; running instances of revisions that left the enabled state are torn down.

```json
{"imported": ["mcp-memory@2026.8.31"], "rejected": ["/srv/smcp/state/library/x: SIGNER_UNKNOWN: …"], "revoked": [], "suspended": [], "errors": []}
```

A package directory whose index was rejected is not retried until its index changes or the Gateway restarts.

## GET /api/v1/packages/receipts

The 100 most recent import receipts (FR-5.4), newest first.

```json
{
  "receipts": [
    {
      "receipt_version": 1,
      "time": "2026-10-17T00:16:20.123Z",
      "actor": "smcpctl",
      "package_dir": "/srv/smcp/state/library/mcp-filesystem/2026.8.31",
      "server_id": "mcp-filesystem",
      "revision": "2026.8.31",
      "index_sha256": "…",
      "artifact_sha256": "…",
      "manifest_sha256": "…",
      "signer_key_id": "7B3357B76507695D",
      "anchor": "operator",
      "result": "accepted",
      "checks": ["components", "signature", "anchor_expiry", "digests", "manifest_schema", "provenance_binding", "anchor_scope", "revocation", "rollback", "artifact_stored"]
    }
  ]
}
```

`result` is `accepted`, `rejected` (with `reason_code` and `error`) or `unchanged`.
