# Real-agent conformance suite

The suite in `scripts/agents` checks that real agent CLIs work through the Gateway (SRS FR-15.8). It starts a fresh Gateway with the bundled reference server in a temporary directory and signs each agent in without a browser. It then drives the agent CLI with one short scripted prompt per scenario. Every result is decided from the Gateway's evidence journal. What the model says is never used as evidence: a model can claim to have called a tool it never called, and the suite has seen that happen.

The results go to `build/agents.json`, the `agents` array of the published status data, and to `build/agents-report.json`, which holds the per-scenario detail.

## Clients

The clients are the local clients of SRS Appendix K, read from [clients/matrix.json](clients/matrix.json) (FR-15.10).

| ID | Client | How it connects | CA trust | Model (default mode) |
|---|---|---|---|---|
| `claude-code` | Claude Code | `--mcp-config` with a Streamable HTTP server and an `Authorization: Bearer ${SMCP_SESSION_TOKEN}` header; `--strict-mcp-config`; `--tools ""` (no built-in tools) | `NODE_EXTRA_CA_CERTS` | `anthropic/claude-haiku-5.5` via the Vercel AI Gateway (`ANTHROPIC_BASE_URL=https://ai-gateway.vercel.sh`, `ANTHROPIC_AUTH_TOKEN`) |
| `codex` | Codex CLI | `-c mcp_servers.smcp={url=…, bearer_token_env_var="SMCP_SESSION_TOKEN", default_tools_approval_mode="approve"}` | `CODEX_CA_CERTIFICATE` with a bundle of the system roots plus the Gateway CA | `openai/gpt-5.1-codex-mini` through a custom provider (`base_url=https://ai-gateway.vercel.sh/v1`, `env_key="AI_GATEWAY_API_KEY"`, `wire_api="responses"`) |
| `hermes` | Hermes Agent | `HERMES_HOME` with `mcp_servers.smcp` (`url`, `headers`, `ssl_verify`); `hermes -z … -t smcp` | `ssl_verify: <ca.crt>` | `anthropic/claude-haiku-5.5`, custom OpenAI-compatible provider |
| `opencode` | OpenCode | `OPENCODE_CONFIG` with a `remote` MCP server and `{env:SMCP_SESSION_TOKEN}`; built-in tools off | `NODE_EXTRA_CA_CERTS` | `vercel/anthropic/claude-haiku-5.5` |
| `gemini` | Gemini CLI | `GEMINI_CLI_SYSTEM_SETTINGS_PATH` with `mcpServers.smcp.httpUrl` and headers | `NODE_EXTRA_CA_CERTS` | `gemini-2.5-flash`; needs `GEMINI_API_KEY` (the AI Gateway does not serve the Gemini API) |
| `goose` | Goose | `XDG_CONFIG_HOME/goose/config.yaml` with a `streamable_http` extension | `SSL_CERT_FILE` (Linux only) | `anthropic/claude-haiku-5.5`, OpenAI-compatible provider |
| `grok-build` | Grok Build | none | none | Always `not-run`: no publicly installable CLI |
| `reference` | the suite's own scripted MCP client | Go SDK client | Go TLS | none; never runs unless named |

A client whose CLI is not installed, or which lacks model credentials, is recorded as `not-run` with the reason.

## Scenarios

Each client gets its own principal (`agents-<id>`, framework set to the client), its own pre-registered OAuth client (`smcp-agents-<id>`) and its own session. The policy has one template, `conformance`:

| Rule | Tool | Purpose |
|---|---|---|
| `conf-allow` | `ref_echo` | allowed call |
| `conf-limited` | `ref_time_now`, `calls_per_minute: 1` | denied call |
| `conf-approve` | `ref_read_file`, `approval: true` | approval-obligated call |
| none | `ref_list_files` | ungranted tool, never presented |

| Scenario | What happens | Pass condition (journal unless stated) |
|---|---|---|
| `signin` | The suite runs the OAuth 2.1 authorization-code flow with PKCE through the sign-in form, as the Session Approver, with the agent's registered client ID and a loopback redirect. The agent receives only the resulting bearer token, through the environment variable `SMCP_SESSION_TOKEN`. | A `session` event with outcome `created`, reason `OAUTH_CODE`, the agent's principal and template `conformance` |
| `catalog` | The suite's probe lists the session's tools with the agent's token. The agent is asked to list its tools and to call `ref_list_files` if present. | The catalog is exactly `ref_echo`, `ref_read_file`, `ref_time_now` (checked on the session's `tools/list`, not on model text) |
| `allowed` | The agent is asked to call `ref_echo` once. | A call to `echo` with `requested`, `authorized` (`permit`) and `delivered` (`release`) phases in this session |
| `denied` | The probe makes one `ref_time_now` call with the agent's token, which uses up the one-call-per-minute window. The agent is then asked to call `ref_time_now` once. | A `denied` event with outcome `deny` and reason `RATE_LIMITED` for `time_now`, and no `dispatched` phase |
| `approval` | The suite watches `smcpctl approvals list --json` and approves the agent's pending approval with `smcpctl approvals approve <id> --yes` while the agent asks to call `ref_read_file`. | `approval` events `requested`, `approved` and `consumed` for `read_file`, and the call `delivered` |
| `ungranted` | Evaluated at the end. | No call to `list_files` ever reached the call pipeline for this session, and the `allowed` scenario passed. Without a successful call, the absence of calls proves nothing. |

After every client has run, the suite stops `smcpd` with SIGTERM and runs `smcpctl journal verify`. A failed verification fails every client that ran.

### Claude Code and approval-obligated tools

Claude Code asks the person before every call to a tool marked `anthropic/requiresUserInteraction` (FR-1.50), even when `--allowedTools` allows the tool. In headless mode (`claude -p`) it refuses such calls itself, and neither `--permission-mode bypassPermissions` nor `--permission-prompt-tool` changes this ("MCP tool requires user interaction; not supported via --permission-prompt-tool"). The refusal is listed in `permission_denials` of the JSON result.

For Claude Code the `approval` scenario therefore passes when two things hold: the output records that local refusal, and no `read_file` call reached the Gateway. The detail then says "Gateway hold not exercised". FR-3.25 (the approval acceptance test with Claude Code) needs an interactive session and is not covered by this suite.

## Running it

Prerequisites: Go, the agent CLIs you want to test, and model credentials.

```
set -a; . ~/.config/smcp-dev/ai-gateway.env; set +a   # provides AI_GATEWAY_API_KEY; never print it
go run ./scripts/agents                               # every client of the matrix
go run ./scripts/agents -clients claude-code,codex
go run ./scripts/agents -clients reference            # no model, no CLI: checks the harness itself
go run ./scripts/agents -local -clients claude-code,codex
```

| Flag | Default | Meaning |
|---|---|---|
| `-clients` | all matrix clients | Comma-separated IDs from the table above |
| `-local` | off | Claude Code and Codex use your own subscription logins (`claude` with model `haiku`; `codex` with your ChatGPT login, `--ignore-user-config`, and the top-level `model` of `~/.codex/config.toml` at low reasoning effort, because a ChatGPT login accepts only some models) instead of the AI Gateway. Recorded as mode `local-login`. |
| `-out` | `build/agents.json` | Status-data results |
| `-report` | `build/agents-report.json` | Per-scenario report with durations, agent exit status and session IDs |
| `-work` | a new temporary directory | Work directory; kept when given |
| `-keep` | off | Keep the temporary work directory |
| `-matrix` | `docs/clients/matrix.json` | Matrix with the pinned versions; a different installed version is noted in `detail` |
| `-timeout` | `4m` | Time limit for one agent prompt |
| `-max-turns` | `4` | Turn limit per prompt where the client has one (Claude Code, Goose) |
| `-dns-only-ca` | off | Diagnostic only: see below. Adds `+dns-only-ca` to the recorded mode. |

The exit status is 1 when any client failed, 2 when the suite itself could not run, and 0 otherwise (`not-run` does not fail).

Without `-local`, Claude Code runs with a temporary `CLAUDE_CONFIG_DIR` and Codex with a temporary `CODEX_HOME`, so your own settings, MCP servers and logins are not used or changed. With `-local` they use your normal configuration directories. The work directory holds, per client, the configuration the suite wrote and `<scenario>.log` with the agent's output, in which the session token and the model key are replaced by `[REDACTED]`. It also holds `smcpd.log` and the instance (`instance/state/journal`).

### Secrets

- The model key reaches each agent only through its environment. The session token travels the same way, and configuration files reference it with `${SMCP_SESSION_TOKEN}`, `{env:SMCP_SESSION_TOKEN}` or `bearer_token_env_var`. Goose is the exception: it does not expand variables in extension headers, so its temporary config file (mode 0600) holds the token. Neither secret ever appears on a command line.
- The Session Approver and administrator passwords are generated per run and stored in owner-only files in the work directory.
- Keep each run small: one short prompt per scenario, four scenario prompts per client, Haiku-class models. A full run of the five installable clients through the AI Gateway costs well under one US dollar.

## Results format

`build/agents.json` follows the status contract (`site/src/lib/status.ts`, `AgentResult`):

```json
[
  {"client": "Codex CLI", "version": "0.142.2", "mode": "ai-gateway", "result": "pass",
   "detail": "passed: signin, catalog, allowed, denied, approval, ungranted (approval: held and approved 1 with smcpctl); journal verify ok"}
]
```

| Field | Values |
|---|---|
| `result` | `pass`, `fail`, `not-run` |
| `mode` | `ai-gateway`, `local-login`, `scripted` (reference client); `+dns-only-ca` is appended for diagnostic runs |
| `detail` | Passed scenarios with notes, or each failed scenario with its reason, then `diagnosis:` when a known cause was found in the agent's logs, then the journal verification result |

## Known findings

| Finding | Clients | Effect | Status |
|---|---|---|---|
| BoringSSL rejects iPAddress name constraints ("unsupported name constraint type"). CP-53 puts `IP 127.0.0.0/8` and `::1/128` constraints on the local CA. | Claude Code (native build, Bun runtime), OpenCode (Bun) | The client never connects to the Gateway, so its tools are missing and every scenario fails. With `-dns-only-ca` both clients pass. Hermes (Python/OpenSSL), Codex (Rust), Goose (Rust, Linux) and Node.js accept the CP-53 CA. | Open. Needs a CP-53 and E-22 decision, for example DNS-only constraints with the listener certificate also naming `localhost`. The suite's `detail` names the cause when it finds the error in the agent's logs. |
| Goose on macOS verifies TLS only against the system keychain | Goose | The Gateway CA cannot be trusted without changing the keychain, which the suite does not do | Goose is `not-run` on macOS and runs in CI on Linux |
| Claude Code refuses FR-1.50-marked tools in headless mode | Claude Code | The Gateway's approval hold cannot be exercised with `claude -p` | By design. See the section above. |

### The `-dns-only-ca` diagnostic

`-dns-only-ca` replaces the instance's server CA and listener certificate before `smcpd` starts. The replacement CA's name constraints permit only DNS `localhost`, with no iPAddress subtrees. This deviates from CP-53, and the results are labelled `+dns-only-ca`. Use it only to confirm that the CA is the one thing keeping a client from connecting. Never publish its results as the client's status.

## Continuous integration

The workflow `.github/workflows/agents.yml` (name "Real agents") runs on pushes to main, nightly and on manual dispatch, where it takes an optional client list. It is not a required check.

1. `scripts/agents/install-clis.sh` installs the CLIs at the versions pinned in `docs/clients/matrix.json`: the npm packages for Claude Code, Codex, OpenCode and Gemini CLI, the Goose release script and the Hermes installer, with the release tag mapped from the pinned version. A client without a pin gets the latest release. A failed install leaves the client `not-run`.
2. `go run ./scripts/agents` runs with the repository secrets `AI_GATEWAY_API_KEY` and, optionally, `GEMINI_API_KEY`.
3. The results, `smcpd.log` and the redacted agent output are uploaded as the artifact `agents-results`. Debug logs and per-client configuration files are not uploaded.
4. On main, the `publish` job commits `agents.json` to the `site-data` branch with `scripts/agents/publish.sh` and replaces the `agents` field of the published `status.json`. The CI `status` job reads `site-data/agents.json` whenever it publishes a new `status.json`, so the results stay on the site between agent runs.

To update a pin, change `pinnedVersion` in `docs/clients/matrix.json`, run the suite locally for that client, and record `lastResult` and `lastRun`.

## Troubleshooting

| Symptom in `detail` | Likely cause | What to do |
|---|---|---|
| `the agent made no call to ref_echo`, `diagnosis: … name constraints …` | BoringSSL client and the CP-53 CA | See Known findings; confirm with `-dns-only-ca` |
| `the agent made no call to …` with no diagnosis | The client did not connect or did not use the tool | Read `<work>/agents/<id>/allowed.log`. For Claude Code, `claude-debug.txt` has the MCP connection log. For OpenCode the output includes debug logs. |
| `ungranted (not proven …)` | No successful call in this run | Fix the `allowed` scenario first |
| `AI_GATEWAY_API_KEY is not set` | No model credentials | Source the key file, or use `-local` for Claude Code and Codex |
| `version X differs from pinned Y` | The installed CLI is not the pinned one | Install the pinned version or update the pin |
| `journal verify FAILED` | The evidence journal did not verify after the run | Treat as a Gateway defect; keep the work directory (`-keep`) and inspect `instance/state/journal` |
