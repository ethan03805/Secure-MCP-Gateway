# Streamable HTTP servers

Planned for v1.3.0 (FR-5.28 to FR-5.30). The Gateway can reach an MCP server over Streamable HTTP instead of launching it as a stdio process. The server is a loopback service, such as the bundled ContextForge instance (FR-22.36), or a remote https endpoint. The code is in `internal/southbound`.

## Configuration

```toml
[[server]]
alias = "cf"
url = "http://127.0.0.1:4444/servers/0f3c.../mcp"
secret_env = { SMCP_UPSTREAM_TOKEN_FILE = "vault:cf-token" }

[[server]]
alias = "remote"
url = "https://mcp.example.com/mcp"
ca_file = "remote-ca.pem"   # optional: the only roots trusted for this server
```

- `url` replaces `command` and `package`; set exactly one of the three. It must be https, or http to `localhost` or a loopback address. User information and fragments are refused.
- `ca_file` names PEM certificates. When it is set, only those roots are trusted for the server's certificate; otherwise the system roots are. Certificate verification cannot be turned off.
- The bearer token is a secret delivered by the Secret Broker, in the slot `SMCP_UPSTREAM_TOKEN` (S4) or `SMCP_UPSTREAM_TOKEN_FILE` (S2, S3). No other `secret_env` slot, and no `args`, `env`, `dir` or `command_sha256`, is accepted with `url`. Without a token slot no `Authorization` header is sent.
- A server with a high-risk class (`code-execution`, `general-sql`, `cad-scripting`, `browser-automation`) is refused with `url` in every profile: it runs outside the Gateway's sandbox.

The Gateway has no OAuth client for servers (planned for v1.4.0, FR-22.45). A server that needs OAuth must be given a token issued outside the Gateway.

## What the Gateway sends

The southbound handshake is the 2025-11-25 era (FR-5.19), as for stdio servers. Each JSON-RPC message is one POST with:

- `Accept: application/json, text/event-stream` and `Content-Type: application/json`;
- `Mcp-Protocol-Version` (the version of the handshake), `Mcp-Method`, and `Mcp-Name` for `tools/call`, `prompts/get` and `resources/read`;
- `Mcp-Param-{name}` for each argument whose input-schema property carries `x-mcp-header`, taken from the tool list the server returned;
- `Mcp-Session-Id` after the server issued one with the initialize response;
- `Authorization: Bearer` when a token is delivered.

`Mcp-Name` and `Mcp-Param-*` values that are not plain header text (non-ASCII, control characters, leading or trailing white space, or text that looks like the sentinel) are sent as `=?base64?...?=` (FR-5.29). Integers are sent in decimal and booleans as `true` or `false`; an absent or null argument sends no header.

When the Gateway closes the instance it sends `DELETE` with the session ID. A cancelled call closes its response stream and sends `notifications/cancelled`.

## What the Gateway accepts

- A JSON response or an SSE response for every request. SSE comment lines are ignored (FR-5.30).
- On a response stream, notifications and server requests before the response. Server requests other than `ping` are refused with `-32601`, as for stdio servers (FR-5.20); progress goes to the caller.
- When a response stream ends before the response and its events carry IDs, the Gateway resumes it with `GET` and `Last-Event-ID`, at most three times.
- When the server declares `tools.listChanged`, a `GET` stream for its notifications; a list change starts the same drift check as for stdio servers.

## Protections

Server messages reach the same dispatcher code as stdio output, so the stdio rules hold: the CP-08 result bound, the JSON-RPC and UTF-8 checks, refusal of server requests, `InputRequiredResult` handling, the upstream timeout, restart after a failure and suspension after three failures in five minutes (FR-5.12). Policy, request and response inspection, approvals and the journal are in front of the dispatcher and apply unchanged.

Transport-specific rules:

| Server behavior | Result |
|---|---|
| A response larger than the bound (JSON body or SSE event) | Read only up to the bound; the result is withheld (`-31003`) |
| A response for another request ID | Dropped; the call fails if its own response does not arrive |
| A JSON-RPC batch, a 202 for a request, an unknown content type, an error status without a JSON-RPC body (for example 403 `{"detail": ...}`) | The call fails as a backend error; the text is kept as server-asserted evidence, never shown to the client |
| A redirect | Not followed; the token is sent only to the configured URL |
| Connection refused or reset, failed certificate verification, response headers over 64 KiB | The instance is treated as failed and replaced |
| HTTP 404 for a request in a session | The session ended: the instance is replaced with a new session |
| Proxy variables in the Gateway's environment | Ignored |
| A host name (or public address) in `url` that resolves to a loopback, link-local, cloud-metadata, multicast or unspecified address | Not connected; the instance fails. Private addresses are allowed. A local server must be named by a loopback URL. |

The transport's diagnostics (refusals and what the server answered) are the instance's `Stderr` and become server-asserted evidence (SR-6.18-1). They never contain the token.

## Not in v1.3.0

- The 2026-07-28 era southbound, with `subscriptions/listen` (FR-5.16, FR-5.31, deferred).
- An OAuth 2.1 client (FR-22.45, v1.4.0).
- Egress grants for remote url servers: the Gateway connects to the configured host directly, not through the Egress Broker, whose one-use capabilities are minted for operations of a server process. The `url` itself is the operator's grant; the address rule above and `ca_file` bound where the connection can go.

The experimental bridge `smcp-stdio --experimental-upstream` from the ContextForge spike still works and uses the same URL and token rules, but a `url` server replaces it.
