# Secure MCP Gateway — Architecture Specification

**Status:** Design only (no implementation)  
**Date:** 2026-09-21  
**Audience:** Local multi-agent workstation (Grinch / Ubuntu 24.04), Hermes Agent + other MCP clients  
**Authoring context:** Hybrid stdio + Docker MCP strategy already adopted for Hermes

---

## 1. Problem statement

Provide a single **Secure MCP Gateway** that all agents on the workstation (and optionally LAN) use as their only path to curated MCP servers, with:

| Capability | Requirement |
|---|---|
| Auth toggle | Authentication can be **enabled or disabled** globally (and optionally per listener) |
| Policy routing | Per-**agent** allow/deny to MCP servers, tools, and actions |
| Audit | Persist **metadata-only** or **metadata + full request/response**; store under an audit directory; include **policy violations** |
| Admin GUI | Configure policy; review/delete audit records; add/remove MCP servers; manage secrets |
| Secrets | Central utility for API keys, OAuth tokens, upstream credentials (never in agent configs) |
| Response filters | Inspect/mitigate MCP responses (e.g. prompt injection, invisible Unicode, secrets leakage) |
| Modularity | Prefer OSS; isolate custom modules behind stable interfaces |

**Non-goals (v1):** Multi-region HA, Kubernetes operator, multi-tenant SaaS billing, replacing Hermes’ native tools.

---

## 2. Viability assessment

### Verdict: **Viable with caveats**

The approach matches the industry “gateway” tier (identity + capability + policy + audit), not a mere transport proxy. Open-source MCP gateways already exist that cover large fractions of aggregation, auth, admin UI, and logging. **No single OSS product fully matches** the exact combination of:

- auth on/off switch with clear local UX,
- agent-centric policy (Agent A vs Agent B) with tool-level granularity,
- dual-mode audit (meta vs full) to a **user-owned audit directory**,
- first-class secrets vault UI,
- pluggable **response content filters** for injection mitigation,

…as a lean workstation appliance. Therefore the recommended path is **compose + thin custom control plane**, not greenfield protocol stack.

### Caveats

1. **Client identity is hard.** Most MCP clients (Hermes, Cursor) present as “a process with a token/URL,” not a rich agent principal. You must **mint per-agent credentials** (API keys / OAuth clients / mTLS) and map those to Agent IDs in policy.
2. **Stdio vs HTTP.** A shared gateway for *all* agents wants **Streamable HTTP (or SSE) on localhost**. Stdio is 1:1 parent/child; use a small **stdio→HTTP adapter** only when a client cannot speak HTTP.
3. **Full-payload audit** stores sensitive tool I/O. Treat the audit directory as sensitive as secrets; support retention, redaction, and delete-from-GUI.
4. **Prompt-injection filters** on *tool results* are imperfect. Prefer layered: structural sanitization + regex/secret scanners + optional ML scanner; never claim perfect prevention.
5. **Heavy gateways** (IBM ContextForge, Microsoft K8s gateway) are overkill for a single Ubuntu box unless you want their admin UI/plugin ecosystem out of the box.

---

## 3. Landscape research (OSS)

### 3.1 MCP-specific gateways / proxies (trade study)

**Protocol note (2025-11-25+):** current MCP stdio is **newline-delimited JSON-RPC** (no embedded newlines; stderr for logs). Older **Content-Length** framing is legacy. Prefer **Streamable HTTP** for the shared gateway listener. Hermes may register tools as `mcp__<server>__<tool>` — policy must use the gateway’s public tool names consistently.

| Candidate | License / stack | Strengths | Gaps vs your requirements | Fit for Grinch |
|---|---|---|---|---|
| **[IBM ContextForge](https://github.com/IBM/mcp-context-forge)** (`mcp-contextforge-gateway`) | Apache-2.0, Python FastAPI + HTMX UI, Docker | Mature federation; auth (JWT/OIDC/SSO); RBAC/teams; admin UI; plugins (PII/deny/regex/OPA/LlamaGuard); OTel; SQLite or Postgres; multi-transport | Agent model is user/team oriented, not “Hermes vs Cursor” principals by default; audit-to-directory / meta-vs-full modes need shaping; heavier ops surface | **Strong baseline / fork-or-extend candidate** |
| **[agentgateway](https://github.com/agentgateway/agentgateway)** | Apache-2.0, Rust | Single binary; stdio/HTTP/SSE/Streamable; JWT/API key/OAuth; CEL + MCP authz; guardrails; standalone UI; OTel | Dual-mode audit directory and full secrets product still gaps; may be more platform than needed | **Top spike peer to ContextForge** for local binary data plane |
| **[ToolHive](https://github.com/stacklok/toolhive)** (Stacklok) | Apache-2.0, Go + UI | Container isolation; structured audit JSON; OIDC; desktop UI; encrypted local secrets | Docker/Podman-centric; agent-principal policy and PI filters not complete | Strong if you want containerized upstreams + audit schema |
| **[MetaMCP](https://github.com/metatool-ai/metamcp)** | MIT, TypeScript | Namespace UI; API key/OAuth endpoints; Compose-friendly | Needs Postgres; PI/audit middleware immature; check maintenance | Good DX reference; weaker as security PDP |
| **[asashiki/mcp-switch](https://github.com/asashiki/mcp-switch)** | Self-hosted; SQLite; console SPA | Aggregate stdio+HTTP; OAuth; console; agent scoping; audit log; auth optional via unset public URL | Small/young project; verify license & maturity; filter plugins likely missing | Interesting lightweight reference |
| **[docker/mcp-gateway](https://github.com/docker/mcp-gateway)** | MIT, Go / Docker MCP Toolkit | Integrates with Docker Desktop; catalog; Desktop secrets; `--block-secrets` | Not a full security control plane | Good for hosting upstream servers, not the whole Secure Gateway |
| **[sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy)** | MIT, Python/uv | Excellent stdio ↔ Streamable HTTP/SSE bridge | Not a multi-server policy gateway (by design) | Required adapter component |
| **[joshrotenberg/mcp-proxy](https://github.com/joshrotenberg/mcp-proxy)** | MIT/Apache, Rust, Tower | Aggregates stdio/HTTP/WS; auth middleware; filtering; single binary | Early; limited admin GUI/secrets/audit directory story | Strong data-plane inspiration or embed |
| **[MikkoParkkola/mcp-gateway](https://github.com/MikkoParkkola/mcp-gateway)** | PolyForm Noncommercial | Rich security/UI, poisoning checks, auth on/off | Commercial use needs a paid license — unsuitable as default OSS base if commercial/redistribution is in scope | Feature ideas only unless licensed |
| **[Kuadrant/mcp-gateway](https://github.com/Kuadrant/mcp-gateway)** / **[microsoft/mcp-gateway](https://github.com/microsoft/mcp-gateway)** | Envoy/Istio / K8s | Enterprise policy attachment, session routing | K8s-native — wrong deployment model for Grinch | Defer |

**OSS recommendation (MCP core):**

1. **Prefer adopt/extend ContextForge** if you want fastest path to Admin UI + auth + plugins + multi-transport.  
2. **Else build a slim custom gateway** (recommended for your exact agent/audit/filter model) and reuse **sparfenyuk/mcp-proxy** (transport) + **Docker MCP Gateway/catalog** (upstream packaging) + embedded policy library.

For a security-architect / SSE-tooling user who wants *exact* audit and agent policy semantics, **slim custom + OSS libraries** is cleaner than fighting ContextForge’s tenancy model — but ContextForge remains the best “buy” if schedule dominates.

### 3.2 Policy engines

| Engine | Role | Recommendation |
|---|---|---|
| **Cedar** (Apache-2.0) | Fine-grained authZ language, analyzable, fast embed | **Primary recommendation** for agent→server→tool→action |
| **Casbin** | Multi-model ACL/RBAC/ABAC library | Good if you want CSV-like policy tables and multi-language ports |
| **OPA/Rego** | General policy-as-code | Overkill for single-box unless you already live in Rego |
| **OpenFGA / SpiceDB** | Relationship graphs | Overkill for ~dozens of agents/servers |

### 3.3 Secrets

| Option | Fit |
|---|---|
| **OpenBao / HashiCorp Vault** (OSS) | Full-featured; heavy for laptop |
| **Infisical** (self-host) | GUI-friendly secrets |
| **SOPS + age** | File-encrypted secrets in git; great for config-as-code |
| **pass / gopass** | Simple local |
| **Docker Desktop / 1Password SDK** | Integrate later |

**Recommendation:** Gateway **Secrets Service** with pluggable backends; v1 backend = **age-encrypted secrets file** or **SQLite sealed with a workstation key** + GUI; v2 optional OpenBao.

### 3.4 Audit storage

| Option | Fit |
|---|---|
| Append-only **JSONL** files under `~/secure-mcp-gateway/audit/YYYY/MM/DD/` | Matches “audit directory”; easy review/delete |
| SQLite index + JSONL payloads | Fast GUI queries |
| OpenTelemetry → local collector | Optional parallel path |

**Recommendation:** JSONL (payloads) + SQLite (index/metadata) under a configurable audit root.

### 3.5 Response filters / injection mitigation

| Option | Notes |
|---|---|
| **Structural** | Strip invisible Unicode TAG chars (Hermes already does this client-side; gateway should too); schema validate tool results |
| **Regex / secret scanners** | Detect keys, tokens, private key PEM |
| **LLM Guard** | Archived / unmaintained — **do not depend on as primary** |
| **NeMo Guardrails** | Powerful but heavy; tool-result content injection not fully covered by structural tool rails |
| **Custom filter plugins** | Interface: `Filter(ctx, mcp_message) -> Allow | Redact | Block` |

**Recommendation:** First-party **Filter Plugin API** with built-ins (invisible-unicode, secrets-regex, max-size, deny-substrings). Optional sidecar calling an external scanner later.

---

## 4. Component decomposition (implementable)

```
┌─────────────────────────────────────────────────────────────────┐
│ Admin GUI (SPA or HTMX)                                         │
│  Policy · Servers · Agents · Secrets · Audit · Filters · Auth   │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTPS localhost (Admin API)
┌────────────────────────────▼────────────────────────────────────┐
│ Control Plane                                                   │
│  Config Store · Policy Engine · Secrets Service · Audit Index   │
│  Server Registry · Agent Registry · Filter Registry             │
└───────┬───────────────────────────────┬─────────────────────────┘
        │ sync (file/NATS/in-proc)      │
┌───────▼───────────────────────────────▼─────────────────────────┐
│ Data Plane — MCP Gateway Runtime                                │
│  Listener(s) → AuthN → AuthZ(policy) → Route → Upstream → Filter│
│                → Audit                                          │
└───────┬─────────────────┬─────────────────┬─────────────────────┘
        │                 │                 │
   Upstream A        Upstream B        Transport Adapters
   (HTTP MCP)        (stdio via        (stdio bridge for
                      mcp-proxy)        legacy clients)
```

### C1 — Agent Registry
- Records: `agent_id`, display name, credential IDs, enabled flag, notes  
- Maps presented auth material → `agent_id`

### C2 — Server Registry
- Records: `server_id`, transport (`stdio`|`http`|`sse`), launch command/URL, env secret refs, tool namespace prefix, health  
- Add/remove/disable without restart (hot reload preferred)

### C3 — Policy Engine
- Inputs: `agent_id`, `server_id`, `tool_name`, `mcp_method`, attrs (time, auth_on, audit_mode)  
- Outputs: `Allow` | `Deny(reason)` | `AllowWithObligations` (e.g. force meta-only audit, force filter profile)  
- Auth global toggle: when auth **off**, either (configurable) deny all external listeners **or** treat caller as `anonymous` with a dedicated policy

### C4 — AuthN Module
- Modes: `off` | `api_key` | `oauth2_oidc` | `mtls`  
- Issues/validates per-agent API keys; optional OIDC for GUI and remote agents  
- Binds tokens to `agent_id`

### C5 — Router / Aggregator
- Implements MCP server façade: `initialize`, `tools/list`, `tools/call`, resources/prompts as enabled  
- `tools/list` is **policy-filtered per agent** (virtual composition)  
- Dispatches `tools/call` to the owning upstream

### C6 — Transport Adapters
- HTTP/SSE/Streamable-HTTP listener (primary)  
- Stdio child manager for local upstreams (or delegate to sparfenyuk/mcp-proxy)  
- Optional outbound stdio wrapper so Hermes can use `command: gateway-stdio-client` if needed

### C7 — Audit Service
- Modes per policy: `off` | `metadata` | `full`  
- Metadata: timestamp, agent_id, server_id, method, tool, decision, latency_ms, sizes, hash of body, violation codes  
- Full: metadata + request/response JSON (optionally compressed)  
- Writers: JSONL under audit directory; SQLite index for GUI  
- Policy denials always audited

### C8 — Secrets Service
- Store/retrieve upstream env secrets and agent API keys  
- Never return raw secrets to agents; inject into upstream process env at spawn  
- GUI: add/rotate/delete; show last-used; no plaintext listing after save (show hint only)

### C9 — Filter Pipeline
- Ordered plugins on **responses** (and optionally requests)  
- Actions: pass, redact fields, replace content, block (returns MCP error to client; audit violation)

### C10 — Admin API + GUI
- CRUD for C1–C9 configuration  
- Audit browser: search, filter by agent/server/violation, view, delete, export  
- Auth toggle control with confirmation

### C11 — Health / Metrics (optional v1.1)
- Upstream health, gateway ready, basic counters (denies, filter blocks)

---

## 5. What must be custom-coded vs reused

| Component | Reuse | Custom |
|---|---|---|
| MCP JSON-RPC framing / client/server SDK | Official MCP SDKs (Python/TS/Go/Rust) | Glue only |
| stdio↔HTTP bridge | sparfenyuk/mcp-proxy or ContextForge translate | Config/packaging |
| Upstream packaging | Docker MCP Gateway / your Compose images | Mounts & names |
| Policy evaluation | Cedar **or** Casbin library | Policy schema, GUI editor, agent mapping |
| Secrets crypto | age / libsodium / OS keyring | Secrets Service API + GUI |
| Admin UI | ContextForge UI (if adopt) **or** lightweight SPA | Almost certainly custom screens for your audit modes |
| Audit JSONL+SQLite | Standard libs | Schema, retention, redaction |
| Injection filters | Regex + optional model scanners | Plugin host + built-ins |
| Auth toggle + agent API keys | OAuth libs (e.g. ory/fosite, or simple HMAC API keys) | Product semantics |
| End-to-end gateway orchestration | ContextForge **or** none | **Thin runtime if not adopting ContextForge** |

**Irreducibly custom (even if ContextForge is base):** agent-centric policy model as you described, dual audit modes to a dedicated directory, auth on/off product behavior, and filter-pipeline obligations tied to policy.

---

## 6. Language trade study (custom runtime)

| Language | Pros | Cons | Verdict |
|---|---|---|---|
| **Go** | Fast compile, static binary, excellent concurrency, easy localhost service, strong crypto/HTTP ecosystem, Casbin-native, simple ops on Ubuntu | UI not native (separate SPA) | **Recommended for data plane + control API** |
| **Rust** | Max performance/safety; joshrotenberg-style proxies | Slower delivery; steeper for GUI/policy glue | Optional hot-path later |
| **Python** | Fastest integration with MCP Python SDK, ContextForge, filter/ML ecosystem | Packaging/perf/GIL; fine for control plane if using ContextForge | **Best if adopting ContextForge**; else secondary for filter workers |
| **TypeScript/Node** | Good MCP SDK; easy SPA sharing types | Weaker as long-lived security gateway binary | GUI + maybe Admin API only |

### Recommendation

- **If build slim custom:** **Go** for Gateway Runtime + Admin API; **TypeScript React/Svelte** for GUI; optional **Python sidecar** only for heavy ML filters.  
- **If adopt ContextForge:** stay on **Python** for core; add Go/Rust only if profiling demands it.  
- **Preferred overall for your brief:** **Go data plane + TS GUI + Cedar policies + Python optional filter worker** — modular and efficient on Grinch.

---

## 7. Final recommended architecture

### 7.1 Strategy

**Compose a workstation Secure MCP Gateway** rather than a K8s mesh:

1. **Primary interface to agents:** Streamable HTTP MCP on `127.0.0.1:9443/mcp` (TLS optional on localhost; TLS required if LAN-bound).  
2. **Per-agent API keys** (when auth on). Hermes / Cursor / others each get a key → `agent_id`.  
3. **Upstream MCP servers** run as: (a) host stdio processes managed by gateway, or (b) Docker Compose services; gateway holds credentials.  
4. **Policy in Cedar** (files editable via GUI).  
5. **Audit root:** `/home/netrisk/secure-mcp-gateway/audit` (configurable).  
6. **Admin GUI:** `https://127.0.0.1:9444/` talking to Admin API.  
7. **Auth master switch** in config + GUI; when off, only loopback accepted and `anonymous` policy applies (default deny for dangerous tools).

### 7.2 Logical deployment on Grinch

```text
/home/netrisk/secure-mcp-gateway/
  bin/smcp-gateway           # Go binary
  config/config.yaml
  policy/*.cedar
  secrets/secrets.age       # or sealed sqlite
  audit/
    index.sqlite
    2026/09/21/*.jsonl
  ui/                       # static GUI assets
docker compose (optional):
  upstream MCP containers published only to gateway network
```

Agents point at **one** MCP URL (or one stdio wrapper command). They do **not** hold upstream secrets.

### 7.3 Request path (normative)

1. Client opens MCP session to Gateway Listener.  
2. **AuthN:** if auth=on, validate bearer/API key → `agent_id`; if auth=off → `agent_id=anonymous` (loopback only).  
3. For `tools/list` / `resources/list` / `prompts/list`: compute **union of allowed** upstream capabilities under policy; return filtered list.  
4. For `tools/call`:  
   a. Resolve tool → `server_id`.  
   b. **AuthZ** Cedar decision. On Deny → MCP error + **audit violation**.  
   c. Inject secrets into upstream call context.  
   d. Forward JSON-RPC to upstream (HTTP or stdio session).  
   e. Run **Filter Pipeline** on response. Block/redact → audit violation codes.  
   f. **Audit** per mode (metadata or full).  
   g. Return result to client.

### 7.4 Policy model (Cedar sketch)

```cedar
// Example shape — illustrative
permit (
  principal == Agent::"hermes",
  action == Action::"tools.call",
  resource == Tool::"projects_fs.read_file"
);

forbid (
  principal == Agent::"cursor",
  action == Action::"tools.call",
  resource is Tool
) when { resource.server == "shell_exec" };

permit (
  principal == Agent::"anonymous",
  action == Action::"tools.call",
  resource is Tool
) when { context.auth_enabled == false && resource.risk == "low" };
```

GUI edits generate Cedar (or an intermediate YAML compiled to Cedar).

### 7.5 Audit record schema (metadata)

```json
{
  "ts": "2026-09-21T23:00:00-04:00",
  "event_id": "uuid",
  "agent_id": "hermes",
  "auth_mode": "api_key",
  "mcp_method": "tools/call",
  "server_id": "projects_fs",
  "tool": "read_file",
  "decision": "allow",
  "violation_codes": [],
  "filter_actions": ["strip_invisible_unicode"],
  "latency_ms": 12,
  "req_bytes": 320,
  "res_bytes": 4410,
  "req_sha256": "...",
  "res_sha256": "...",
  "audit_level": "metadata"
}
```

Full mode adds `request` and `response` objects (or sidecar `.jsonl` payload files referenced by `event_id`).

### 7.6 Admin GUI capabilities (v1)

- Toggle **Authentication** on/off (with warning).  
- Agents: create, revoke key, disable.  
- Servers: add HTTP or stdio upstream; enable/disable; test connection.  
- Policy: matrix or form → Cedar; simulate decision.  
- Filters: enable built-ins; order pipeline; assign profiles to agents/servers.  
- Secrets: create/rotate/delete references used by servers.  
- Audit: search, open detail, delete one/many, export; show violations prominently.  
- System: audit directory path, retention days, listen addresses.

### 7.7 Hermes / agent integration

**Hermes (`~/.hermes/config.yaml`):**

```yaml
mcp_servers:
  secure_gateway:
    url: "http://127.0.0.1:9443/mcp"
    headers:
      Authorization: "Bearer ${SECURE_MCP_HERMES_KEY}"
```

Store the key in `~/.hermes/.env` as `SECURE_MCP_HERMES_KEY`, issued by the Gateway GUI.

**Cursor / others:** same URL + distinct API key → distinct `agent_id` → distinct tool visibility.

**Stdio-only client:**  
`command: smcp-stdio-client` with env `SECURE_MCP_URL` + key (thin wrapper speaking stdio to the client and HTTP to the gateway).

### 7.8 Security properties (design intent)

- Single chokepoint for tool egress from agents.  
- Least privilege via per-agent virtual tool lists.  
- Secrets never distributed to agent configs.  
- Denies and filter blocks are first-class audit events.  
- Auth-off is an explicit, logged degraded mode, not silent failure.  
- Bind default to loopback; LAN bind requires auth=on.

### 7.9 Phased delivery (still design — no code)

| Phase | Scope |
|---|---|
| **P0** | Go gateway: HTTP MCP façade, API-key auth toggle, static allowlist policy, stdio+HTTP upstreams, metadata audit JSONL, minimal GUI or CLI |
| **P1** | Cedar policies, full/meta audit + SQLite index, secrets service, filter pipeline built-ins, Admin GUI |
| **P2** | Hot reload, retention/redaction, OIDC for GUI, Docker network integration, optional ML filter sidecar |
| **P3** | Remote agents (mTLS/OpenZiti), SIEM export, HA (only if needed) |

### 7.10 Decision: adopt ContextForge vs slim custom

| Criterion | Winner |
|---|---|
| Time-to-admin-UI | ContextForge |
| Exact agent/audit/filter semantics | Slim custom (Go) |
| Aligns with Docker Desktop on Grinch | Both (Compose either way) |
| Long-term modular security product you control | **Slim custom** |
| Avoid maintaining MCP protocol edge cases | ContextForge |

**Final call:** **Slim custom Secure MCP Gateway in Go** with OSS adapters (mcp-proxy, Docker for upstreams, Cedar, age), **unless** a spike shows ContextForge plugins can express agent policy + dual audit with &lt;2 weeks of work — then adopt ContextForge and custom-plugin the gaps.

**Spike gate (before coding):** 1–2 day evaluation on Grinch of **ContextForge** and **agentgateway** (peer spikes): (1) two API identities with different tool sets, (2) export/copy audit to a directory with full payloads, (3) regex deny filter on tool results. Pass on either → extend that base. Fail both → execute slim custom architecture (Go or Rust data plane + Cedar + TS GUI). See also `Secure-MCP-Gateway-Research-Brief.md`.

---

## 8. Interface contracts (specification-level)

### 8.1 Admin API (REST, localhost)

- `GET/PUT /api/v1/system/auth` — `{ enabled: bool }`  
- `CRUD /api/v1/agents`  
- `CRUD /api/v1/servers`  
- `GET/PUT /api/v1/policy`  
- `POST /api/v1/policy/simulate`  
- `CRUD /api/v1/secrets` (write-only values)  
- `CRUD /api/v1/filters`  
- `GET /api/v1/audit?query=` / `DELETE /api/v1/audit/{id}` / `POST /api/v1/audit/export`

### 8.2 Filter plugin ABI

```text
OnMessage(phase: request|response, msg: JsonValue, ctx: {agent,server,tool})
  -> { action: pass|redact|block, msg?: JsonValue, codes?: string[] }
```

Plugins: in-process Go first; Python worker via gRPC optional.

### 8.3 Config file (sketch)

```yaml
listen:
  mcp: "127.0.0.1:9443"
  admin: "127.0.0.1:9444"
auth:
  enabled: true
  type: api_key
audit:
  root: /home/netrisk/secure-mcp-gateway/audit
  default_level: metadata   # metadata | full | off
  retention_days: 90
policy:
  engine: cedar
  path: ./policy
secrets:
  backend: age
  path: ./secrets/secrets.age
```

---

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Agents bypass gateway by talking to upstream directly | Firewall/user discipline; upstreams bind to docker-internal or stdio-only; document “no direct URLs in agent configs” |
| Full audit becomes a secret store | Encrypt audit at rest option; retention; GUI delete; default metadata |
| Filter false positives | Dry-run mode; per-server filter profiles; audit-only initially |
| MCP protocol drift | Use official SDKs; conformance tests; pin protocol version |
| Auth off accidents | GUI warning; auto loopback-only; startup banner in logs |

---

## 10. Summary recommendation

Build a **modular Secure MCP Gateway** as the sole MCP front door for Hermes and peer agents on Grinch. Reuse OSS for **transport bridging** and **upstream packaging**; implement **auth toggle, agent policy, dual-mode audit, secrets GUI, and filter pipeline** as first-class modules. Prefer **Go + Cedar + TS admin UI**, with a short **ContextForge spike** as a go/no-go for “extend vs build.” Do not implement K8s/Envoy-class gateways for this workstation use case.

---

## References

- IBM ContextForge: https://github.com/IBM/mcp-context-forge  
- agentgateway: https://github.com/agentgateway/agentgateway  
- ToolHive: https://github.com/stacklok/toolhive  
- MetaMCP: https://github.com/metatool-ai/metamcp  
- sparfenyuk/mcp-proxy: https://github.com/sparfenyuk/mcp-proxy  
- docker/mcp-gateway: https://github.com/docker/mcp-gateway  
- asashiki/mcp-switch: https://github.com/asashiki/mcp-switch  
- TrueFoundry portal/router/gateway framing: https://www.truefoundry.com/blog/mcp-gateway-vs-proxy-vs-router  
- Research brief (detailed tables): `Secure-MCP-Gateway-Research-Brief.md`  
- Hermes MCP client config: `~/.hermes/config.yaml` `mcp_servers`  
