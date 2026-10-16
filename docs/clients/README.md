# Client quick starts

How to connect each client of the SRS Appendix K matrix to the Gateway. The machine-readable matrix, with pinned versions and the latest results, is `matrix.json` in this directory (FR-15.10). Per-client quick starts are required by FR-18.3.

**Status.** The first slice (commit a3193a5) supports the Claude Code path in Section 1 with the Administrator password at sign-in. `smcp-session`, `smcp-stdio`, `smcp-connect`, `smcpctl client setup`, `smcpctl lockdown` and `smcpctl doctor` are specified (FR-12.12, FR-12.13, FR-15, FR-16.9) and not yet released; the sections below that use them describe the specified procedure.

## Common steps

1. Install and start the Gateway (`docs/install.md` once published; until then, the README's "Running the first slice").
2. Create a Session Approver account for sign-ins (FR-2.23).
3. Make the client trust the Gateway CA: `smcpctl client setup <client>` (FR-15.7). It never changes the system trust store unless you pass `--system-trust`.
4. Apply the lockdown profile: `smcpctl lockdown apply <client>` (FR-15.1), then run `smcpctl doctor` and resolve every finding (FR-15.3, FR-15.4).
5. Connect the client and sign in in the browser as the Session Approver.

## 1. Claude Code

```
export NODE_EXTRA_CA_CERTS=<state dir>/tls/ca.crt
claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
```

Claude Code discovers the OAuth metadata, opens a browser and receives a session token. Tools appear as `mcp__smcp__<alias>_<tool>`. Tools that require approval carry `anthropic/requiresUserInteraction`, so Claude Code also prompts locally.

Lockdown (FR-15.2): a managed settings file that allows only the `smcp` server and denies Claude Code's `Read` and `Edit` tools on the Gateway's directories and the credential file.

## 2. Codex CLI

Add the Gateway as a URL server with OAuth (`codex mcp login smcp`), or use `http_headers_helper = "smcp-session"`. Lockdown uses the administrator requirements file's MCP server allowlist where the pinned version supports it. Codex is treated as a 2025-11-25 client until it is confirmed otherwise.

## 3. Hermes Agent

Configure an HTTP MCP server with `auth: oauth`, or a static `Authorization` header from `smcp-session`. Point `ssl_verify` at the Gateway CA bundle. Hermes has no documented administrator allowlist; `smcpctl doctor` reports any other configured servers.

## 4. OpenCode

Configure a remote MCP server pointing at `https://127.0.0.1:8443/mcp`, or a local MCP server running `smcp-stdio`. Lockdown uses OpenCode's `mcp` and `permission` configuration; whether a scope exists that the user and agent cannot write is confirmed at pinning.

## 5. Gemini CLI

Configure `httpUrl` for the Gateway in the system settings file and restrict MCP servers to it. Google states that the name-based allowlist is not a security boundary, so Gemini CLI stays labelled `gateway-available` until the bypass tests pass.

## 6. Goose

Add a stdio extension whose command is `smcp-stdio`. Set `GOOSE_ALLOWLIST` to a YAML allowlist that contains only that command.

## 7. Grok Build

Use `smcp-stdio` wherever Grok Build accepts a stdio MCP command. Its configuration and lockdown mechanism are recorded at pinning.

## 8. Cloud agents: Grok Bot, ChatGPT agent "dots", Meta Muse

These agents run on the vendor's computer and cannot reach `127.0.0.1`. Use the Remote Access Profile (FR-16):

1. As Administrator: `smcpctl remote enable --public-name <name>` (FR-16.11). This opens a second listener on `127.0.0.1:8444` only.
2. Run a tunnel connector on your computer that forwards `https://<name>` to `https://127.0.0.1:8444`: Cloudflare Tunnel, Tailscale Funnel, or the vendor's MCP tunnel where offered. Check it with `smcpctl remote check` (FR-16.2).
3. In the vendor's admin settings, where offered, restrict the agent's MCP servers to `https://<name>/mcp` (FR-16.10).
4. Add the Gateway URL in the agent. When it registers, approve the registration: `smcpctl clients approve <client-id>` (FR-16.5).
5. Sign in as Session Approver when the browser prompt appears.
6. If the agent accepts only a command, use `npx smcp-connect --url https://<name>/mcp` (FR-16.9).

Read `docs/security-limitations.md` items 5 and 6 before enabling remote access: the tunnel provider can read the traffic, and the agent's own browser, terminal and connectors do not pass through the Gateway.
