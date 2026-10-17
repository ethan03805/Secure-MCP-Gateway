# Cloud agents: Grok Bot, ChatGPT, Meta Muse

These agents run on the vendor's computer and cannot reach `127.0.0.1`. They connect through the Remote Access Profile (FR-16, `docs/remote-access.md`). Their own browser, terminal and connector tools are outside the Gateway's control, and the tunnel provider can read the traffic (`docs/security-limitations.md`).

Status: the Remote Access Profile, Dynamic Client Registration with operator approval, the device flow and `smcp-connect` are implemented and tested against a local test tunnel. No cloud agent has been connected in a dated manual run yet (FR-15.9); every cloud entry in `matrix.json` is `not-run`. Vendor allowlist settings were not checked against vendor documentation for this release (checked 2026-10-16: no primary documentation reviewed), so each is stated below as not confirmed.

## Common setup

1. Configure `[remote]` (`docs/remote-access.md`): at least `default_principal` (a principal for cloud agents) and `templates` (the templates a remote session may use; keep them narrow).
2. Enable remote access with a tunnel, as the Gateway's user:

   ```
   smcpctl remote enable --provider tailscale          # https://<machine>.<tailnet>.ts.net
   smcpctl remote check
   ```

   Use `--provider cloudflare` for a Cloudflare quick tunnel (new random `trycloudflare.com` name on every start, no uptime guarantee) or `--provider manual --public-url https://<name>` for a tunnel you run yourself, including a vendor's MCP tunnel.
3. Add `https://<public name>/mcp` as an MCP server or connector in the agent.
4. The agent registers itself; approve it: `smcpctl clients list --status pending`, then `smcpctl clients approve <client-id>`.
5. Sign in as a Session Approver on the page the agent opens (it says the request came through the tunnel).
6. When finished: `smcpctl remote disable` (ends remote sessions and stops the tunnel).

If the agent accepts only a command to run (a cloud coding sandbox), run `npx smcp-connect --url https://<public name>/mcp` there; it registers, waits for your approval, prints a device code to enter at `https://<public name>/oauth/device`, and then relays (`docs/adapters.md`).

## Grok Bot (xAI)

- Connection: remote MCP URL through the tunnel, or `smcp-connect` where the agent accepts only a command.
- Registration: Dynamic Client Registration with operator approval, or a pre-registered client listed in `remote.clients`.
- Vendor allowlist (FR-16.10): not confirmed whether xAI offers an administrator setting that restricts Grok's MCP servers to the Gateway URL (checked 2026-10-16). Until confirmed, treat it as not offered.
- Matrix: `not-run`.

## ChatGPT agent "dots" and ChatGPT custom connectors (OpenAI)

- Connection: add a custom connector (MCP server URL) `https://<public name>/mcp`. ChatGPT connects from OpenAI's servers through the tunnel; OpenAI's own MCP tunnel, where offered, is used with `--provider manual` (or `vendor`) and its public URL.
- Registration: Dynamic Client Registration with operator approval (the connector registers when added), or a pre-registered client.
- Vendor allowlist (FR-16.10): workspace administrator connector and MCP controls exist for business workspaces according to the SRS sources, but the exact setting that limits connectors to one URL was not confirmed (checked 2026-10-16).
- Matrix: `not-run`.

## Meta Muse (Meta)

- Connection: remote MCP URL through the tunnel, or `smcp-connect`.
- Registration: to be confirmed; both Dynamic Client Registration and pre-registered clients are supported by the Gateway.
- Vendor allowlist (FR-16.10): not confirmed whether one is offered (checked 2026-10-16).
- Matrix: `not-run`.

## Limitations

- Per-address limits use the address the tunnel reports; it is recorded as `server-asserted`.
- Templates come from `remote.templates`, not a `remote_allowed` mark in the policy (FR-16.12 deviation, documented in `docs/remote-access.md`).
- The tunnel must preserve the public `Host` header; `smcpctl remote check` reports a tunnel that does not.
