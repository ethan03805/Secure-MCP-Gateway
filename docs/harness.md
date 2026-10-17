# Client setup, lockdown and doctor

`smcpctl` configures the AI clients (harnesses) of SRS Appendix K to use the Gateway, restricts them to it where the client offers a mechanism, and reports what it cannot restrict (FR-15). The commands change files of the user who runs them; run them as the user who runs the clients. Client IDs: `claude-code`, `codex`, `gemini-cli`, `goose`, `grok-build`, `hermes`, `opencode` (aliases: `claude`, `codex-cli`, `gemini`, `grok`).

The lockdown profiles are only as strong as each client's own settings enforcement, and in the Standalone profile the clients run under the Gateway's identity (`docs/security-limitations.md`).

## smcpctl clients setup

```
smcpctl clients setup <client> [--dry-run] [--stdio] [--helper] [--no-lockdown] [--system-trust]
smcpctl clients setup <client> --remove
smcpctl client setup <client> ...          # same command (FR-12.7 spelling)
```

Writes the client's MCP configuration pointing at the Gateway (server name `smcp`), the client's CA trust setting where the client has one (FR-15.7), and then the lockdown profile (unless `--no-lockdown`). `--dry-run` prints every file it would create or update with the full new content, and the commands it would run, and writes nothing.

| Flag | Effect |
|---|---|
| `--stdio` | Connect through `smcp-stdio` even where the client supports Streamable HTTP; no CA trust needed in the client |
| `--helper` | Claude Code: HTTP with `headersHelper = smcp-session`. Other clients: HTTP instead of the default `smcp-stdio` |
| `--no-lockdown` | Connection and CA trust only |
| `--system-trust` | Also add the Gateway CA to the operating-system trust store: on macOS `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <ca>`, on Linux `sudo cp <ca> /usr/local/share/ca-certificates/smcp-gateway.crt` and `sudo update-ca-certificates`. Without this flag the system trust store is never changed |
| `--remove` | Restore every file the previous setup and lockdown changed |

What each client gets:

| Client | Connection (default) | CA trust | Files |
|---|---|---|---|
| Claude Code | Streamable HTTP with OAuth sign-in (register Claude Code's client ID or allowlisted metadata document in `[[client]]` first); `--helper` adds `headersHelper`; `--stdio` uses `smcp-stdio` | `env.NODE_EXTRA_CA_CERTS` in `~/.claude/settings.json` | `~/.claude.json` (`mcpServers.smcp`), `~/.claude/settings.json` |
| Codex CLI | `smcp-stdio` (`[mcp_servers.smcp] command`) | not needed; HTTP trust mechanism to be confirmed at pinning | `~/.codex/config.toml` (managed block) |
| Hermes Agent | Streamable HTTP, `auth: oauth` | `ssl_verify: <ca>` | `~/.hermes/config.yaml` (managed block) |
| OpenCode | `smcp-stdio` (`mcp.smcp`, `type: local`) | not needed | `~/.config/opencode/opencode.json` |
| Gemini CLI | `smcp-stdio` (`mcpServers.smcp.command`) | not needed; HTTP needs `NODE_EXTRA_CA_CERTS` in the environment | `~/.gemini/settings.json` |
| Goose | stdio extension `smcp-stdio` | not needed | `~/.config/goose/config.yaml` (managed block) |
| Grok Build | prints the stdio command to configure; configuration location to be confirmed at pinning | not needed | none |

`smcp-stdio` and `smcp-session` need the credential file (`smcpctl clients credentials`, see `docs/adapters.md`); setup says so when it is missing.

JSON files are rewritten with the new key (the original bytes are kept in the backup). TOML and YAML files get a block between `# BEGIN smcp (managed by smcpctl; remove with smcpctl)` and `# END smcp`; when the file already defines the entry, or already has a top-level `mcp_servers:` or `extensions:` section outside the block, setup stops and prints the block to add by hand. JSON files with comments are refused for the same reason.

## smcpctl lockdown

```
smcpctl lockdown show <client>
smcpctl lockdown apply <client> [--dry-run]
smcpctl lockdown remove <client> [--dry-run]
```

| Client | Lockdown profile (FR-15.1) |
|---|---|
| Claude Code (FR-15.2) | Managed settings file (`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS, `/etc/claude-code/managed-settings.json` on Linux): `allowManagedMcpServersOnly: true`; `allowedMcpServers` with `{"serverUrl": "<gateway MCP URL>"}` and `{"serverCommand": ["smcp-stdio"]}` (URL and command entries, because Claude Code documents `serverName` entries as not a security control); `permissions.deny` with `Read(//<path>/**)` and `Edit(//<path>/**)` for the Gateway state and configuration directories and the credential file, and `Edit(...)` for `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/settings.local.json`, `./.mcp.json`, `./.claude/settings.json` and `./.claude/settings.local.json` (SR-4.11-1). The file is system-wide: run `sudo --preserve-env=HOME smcpctl lockdown apply claude-code --config <config>` (and `remove` the same way) or deploy it through MDM. `allowManagedMcpServersOnly` across managed sources needs Claude Code v2.1.273 or later |
| Codex CLI | Writes `~/.config/smcp/codex-requirements.toml` with `[mcp_server_allowlist.smcp] command = "smcp-stdio"`, to deploy as the Codex administrator requirements (on macOS the `com.openai.codex` `requirements_toml_base64` preference). Key names come from Codex PR #9101 and are to be confirmed at pinning |
| Gemini CLI | System settings (`/Library/Application Support/GeminiCli/settings.json`, `/etc/gemini-cli/settings.json`): `mcpServers.smcp` and `mcp.allowed = ["smcp"]`. Google states name allowlists are not a security boundary |
| Goose | Writes `~/.config/smcp/goose-allowlist.yaml` (only `smcp-stdio`); set `GOOSE_ALLOWLIST` to it in Goose's environment (to confirm at pinning) |
| Hermes, OpenCode, Grok Build | No mechanism (Appendix K); nothing is written and doctor reports the gaps |

`apply` copies every existing file it changes to `<file>.smcp-backup-<UTC timestamp>` and records a manifest in `~/.config/smcp/harness/<client>-lockdown.json` (setup uses `<client>-setup.json`). Applying again while a manifest exists is refused. `remove` copies each backup back byte for byte, deletes files that did not exist before, then deletes the backups and the manifest (FR-15.6). Remove lockdown before setup when both were applied.

## smcpctl doctor

```
smcpctl doctor [--client <id>]... [--json]
```

Checks every installed client (configuration directory or binary present), or the named ones:

| Kind | Fails | What |
|---|---|---|
| `non-gateway-server` | yes | An MCP server in the client's user, project, local or managed scope that is not the Gateway (FR-15.3, SR-4.9-1). The Gateway is recognised by URL origin (harness listener, public URL, Remote Access public URL) or by the command `smcp-stdio` / `smcp-connect` (also through `npx`) |
| `readable-path` | yes | A Gateway path (state directory, configuration directory unless it contains the current project, existing CP-46 directories, the credential file) that this user can read (FR-15.4) |
| `settings-writable` | yes | A client MCP or permission settings file this user (and so the client's own file tools) can write and that no lockdown deny rule protects (SR-4.11-1) |
| `prerequisite` | yes | A failed enforced-profile prerequisite while the configuration asks for the Enforced profile |
| `info` | no | Standalone statement ("clients run under the Gateway's own user identity"), clients without a lockdown mechanism, CA trust state, prerequisites that do not pass outside the Enforced profile |
| `warning` | no | The Gateway is not configured in a client; unreadable configuration files; unknown client names |

Doctor exits 1 when any failing finding is reported and 0 otherwise (FR-15.5); `--json` prints the same findings with the server inventory. In the Standalone profile the Gateway state is readable by the user running the clients by construction, so doctor always reports `readable-path` findings there.

Doctor also runs the sandbox element's enforced-profile prerequisite checks (the same checks as `smcpctl runtime doctor`). Each one that does not pass is reported; a failed prerequisite is a failing `prerequisite` finding when `[profile] mode = "enforced"`, and `info` otherwise.

Configuration locations read:

| Client | Files |
|---|---|
| Claude Code | `~/.claude.json` (`mcpServers` and `projects.*.mcpServers`), `./.mcp.json`, managed `managed-mcp.json` and `managed-settings.json` (`managedMcpServers`) |
| Codex CLI | `~/.codex/config.toml`, `./.codex/config.toml` (`mcp_servers`) |
| Hermes Agent | `~/.hermes/config.yaml` (`mcp_servers`) |
| OpenCode | `~/.config/opencode/opencode.json`, `./opencode.json` (`mcp`) |
| Gemini CLI | `~/.gemini/settings.json`, `./.gemini/settings.json`, system settings (`mcpServers`) |
| Goose | `~/.config/goose/config.yaml` (`extensions`) |
| Grok Build | not known; reported as a warning |
