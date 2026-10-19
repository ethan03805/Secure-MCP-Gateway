# Claude Code

Status: option B below and the lockdown are run by the `lockdown` job of the Real agents workflow (`scripts/agents/lockdown.go`, `docs/agents-conformance.md`) with Claude Code 2.1.302 on Linux. On 2026-10-19 (run 39184564500) Claude Code connected over TLS with only what `smcpctl clients setup claude-code --helper` wrote and called a tool through the Gateway; with the lockdown applied, a second MCP server in user and project scope did not load, the Read of a file in the Gateway state directory and the Edit of `./.mcp.json` were refused ("denied by your permission settings"), and `smcpctl doctor` flagged both extra servers. Option A needs a browser sign-in and is not run by CI. CP-53 CAs carry DNS-only name constraints, which the native build (BoringSSL) accepts; an instance CA made before that change must be replaced with `smcpctl keys rotate ca`.

## Connect

Option A, OAuth sign-in (default). Claude Code discovers the Gateway's OAuth metadata, opens a browser, and a Session Approver signs in. Claude Code's client ID (or its Client ID Metadata Document URL) must be a `[[client]]` with `redirect_uris = ["http://localhost:*/callback"]`.

```
smcpctl clients setup claude-code --dry-run
smcpctl clients setup claude-code --no-lockdown
```

This writes `mcpServers.smcp = {"type": "http", "url": "https://127.0.0.1:8443/mcp"}` to `~/.claude.json` and `env.NODE_EXTRA_CA_CERTS = <state>/tls/ca.crt` to `~/.claude/settings.json`. The manual equivalent:

```
export NODE_EXTRA_CA_CERTS=<state dir>/tls/ca.crt
claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
```

Option B, header helper (no browser step): `smcpctl clients credentials --client-id <id> --secret-file <file>`, then `smcpctl clients setup claude-code --helper`, which adds `"headersHelper": "smcp-session"`.

Option C, stdio: `smcpctl clients setup claude-code --stdio` configures `smcp-stdio`; no CA trust is needed in Claude Code.

Tools appear as `mcp__smcp__<alias>_<tool>`. Tools that require approval carry `anthropic/requiresUserInteraction`, so Claude Code also asks locally.

## Lockdown (FR-15.2)

```
smcpctl lockdown show claude-code
sudo --preserve-env=HOME smcpctl lockdown apply claude-code --config <config>
```

The managed settings file (`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS, `/etc/claude-code/managed-settings.json` on Linux, mode 0644 so that Claude Code running as the user can read it) sets `allowManagedMcpServersOnly: true`, allows only the Gateway URL and the `smcp-stdio` command, and denies Claude Code's `Read` and `Edit` tools on the Gateway's state and configuration directories and the credential file, and `Edit` on Claude Code's own MCP and settings files. Claude Code's managed settings cannot be overridden from user or project settings. Remove with `sudo --preserve-env=HOME smcpctl lockdown remove claude-code`.

## Verify

```
smcpctl doctor --client claude-code
claude mcp list
```

Doctor lists every MCP server in user (`~/.claude.json`), local (`projects.*`), project (`.mcp.json`) and managed scope and flags each one that is not the Gateway. With the lockdown applied, `claude mcp add --transport http other https://example.com/mcp` should be refused by Claude Code ("not allowed by enterprise policy").
