# Secure MCP Gateway — Research Brief

**Date:** 2026-09-21 EDT  
**Target host:** Ubuntu workstation "Grinch" (local/self-hosted)  
**Primary clients:** Hermes Agent (`~/.hermes/config.yaml` → `mcp_servers` with `command`/`url`) and other MCP agents  
**Method:** WebSearch + WebFetch of primary docs/repos; stars/activity are point-in-time from fetches (~2026-09-21). Speculative items labeled.

---

## 0. MCP protocol realities (constraints for any design)

| Fact | Implication |
|------|-------------|
| **JSON-RPC** over transports | Gateway must parse/route by method (`tools/list`, `tools/call`, etc.), not just HTTP path |
| **stdio** (current spec 2025-11-25+): newline-delimited JSON-RPC; **MUST NOT** embed newlines; stderr for logs | Older Content-Length framing is **legacy**; some gateways explicitly drop it (e.g. jadchene/mcp-gateway) |
| **Streamable HTTP**: single endpoint POST+GET; optional SSE streams; `MCP-Session-Id`; `MCP-Protocol-Version` header | Prefer this over deprecated HTTP+SSE (2024-11-05) |
| **Tool name prefixing** | Hermes registers `mcp__<server>__<tool>`; gateways use namespaces (`server/tool`, `server_tool`, etc.) — map carefully for policies |
| **Hermes client** | `mcp_servers.<name>.command|args|env` (stdio) **or** `url|headers` (HTTP); optional `auth: oauth`, tool include/exclude, `trust: untrusted` |
| **Auth toggle** | Spec + clients expect ability to run open on loopback; production needs JWT/API key/OAuth |

---

## 1. Landscape summary

The MCP gateway space (2025–2026) has three layers:

1. **Transport bridges** — stdio↔HTTP/SSE (e.g. sparfenyuk/mcp-proxy). Necessary glue; not governance.
2. **Aggregation / meta-MCP proxies** — many backends → one endpoint, often with tool-discovery compaction (MetaMCP, joshrotenberg/mcp-proxy, MikkoParkkola/mcp-gateway, mcpmux).
3. **Governed platforms** — authN/Z, admin UI, audit, plugins, multi-tenancy (IBM ContextForge, agentgateway, ToolHive, MCPG). Closest to the Secure MCP Gateway requirements.

**No single OSS project fully meets all six requirements out of the box** (auth toggle + agent→server policy routing + dual-mode audit directory + full GUI for policy/audit/servers/secrets + response filters + modular OSS). Closest **platforms**: ContextForge, agentgateway (standalone), ToolHive, MetaMCP. Closest **lightweight binary**: joshrotenberg/mcp-proxy. Closest **security-heavy single binary**: MikkoParkkola/mcp-gateway (**PolyForm Noncommercial** — commercial use needs a license).

**Hermes fit:** Point Hermes at gateway via `url: http://127.0.0.1:<port>/mcp` (+ `headers` for API key) **or** stdio wrapper (`command` launching gateway/wrapper). Prefer HTTP for multi-agent shared gateway; stdio for single-agent isolation.

---

## 2. Top MCP-specific gateway/proxy candidates

### Comparison table

| Candidate | URL | License | Lang | Stars* | Stdio↔HTTP | Multi-server | Auth on/off | Agent→server policy | Audit | Admin GUI | Secrets UI | Response filters | Local Ubuntu fit |
|-----------|-----|---------|------|--------|------------|--------------|-------------|---------------------|-------|-----------|------------|------------------|------------------|
| **IBM ContextForge** | github.com/IBM/mcp-context-forge | Apache-2.0 | Python (FastAPI) | ~4.5k | Yes (translate + wrapper) | Yes | Yes (`AUTH_REQUIRED`) | RBAC + plugin OPA; not first-class “Agent A→server X” | Logs/OTel/security_events; not “audit dir modes” as specified | **Yes** HTMX Admin UI | Vault plugin / encrypted vault; limited secrets *manager* GUI | Plugin hooks: PII, content mod, LlamaGuard external | **Excellent** PyPI/`uvx`/Docker; SQLite OK |
| **agentgateway** | github.com/agentgateway/agentgateway · agentgateway.dev | Apache-2.0 | Rust | ~5.0k | Yes (stdio/HTTP/SSE/Streamable) | Yes (federation) | JWT/API key/OAuth | CEL + MCP authz; RBAC | OTel metrics/logs/traces | Built-in UI (standalone editable) | Backend auth keys; not full secrets product | Guardrails: regex, Bedrock, Model Armor, webhooks | **Excellent** single binary; LF/AAIF project |
| **ToolHive** | github.com/stacklok/toolhive | Apache-2.0 | Go (+ UI) | ~2.2k | Containerized + proxy | Virtual MCP / gateway | OIDC/OAuth | Access policies | Structured audit JSON (`audit.enabled`); ship via Fluent Bit | Desktop UI + CLI | Encrypted secrets (local) | Container isolation; optimizer | **Good** if Docker/Podman; heavier than bare binary |
| **MetaMCP** | github.com/metatool-ai/metamcp | MIT | TS (Next.js + Express) | ~2.7k | Upstream stdio; endpoint SSE/Streamable | Namespaces | API key / OAuth; disableable | Namespace enable/disable tools; not rich PDP | File logs; middleware roadmap | **Yes** web UI | Env `${VAR}` for stdio secrets | Middleware extensible (limited built-in PI) | **Good** Docker Compose; needs Postgres |
| **joshrotenberg/mcp-proxy** | github.com/joshrotenberg/mcp-proxy | MIT/Apache | Rust | ~14 | stdio/HTTP/WS backends → HTTP | Yes | Bearer/JWT; optional | RBAC allow_tools per role | Structured audit + admin API | Admin HTTP API (no full GUI) | Env injection | Filter/alias; not LLM PI scanners | **Excellent** single binary + TOML |
| **Docker mcp-gateway** | github.com/docker/mcp-gateway | MIT | Go | ~1.6k | Catalog/container focus | Yes | OAuth; Desktop secrets | Profiles/catalog | Logging | Docker Desktop / CLI | Docker Desktop keychain / `.env` | `--block-secrets` | **Good** if Docker-centric on Grinch |
| **MikkoParkkola/mcp-gateway** | github.com/MikkoParkkola/mcp-gateway | **PolyForm-NC** | Rust | ~57 | stdio/HTTP/SSE | Yes + REST caps | Auth on/off; per-client scopes | Per-client tool scopes; identity grants | Audit/events; dashboard | Embedded `/ui` | Key server / OAuth isolation | Firewall + tool-poisoning validator | **Strong technically**; **license caveat for commercial** |
| **MCPG** | mcpg.dev | (docs: OSS binary; confirm license on install) | Rust | n/a (docs site) | HTTP + stdio | Backends/plugins | OIDC/mTLS/API key/anon loopback | Cedar, OPA, Casbin plugins | Tamper-evident audit ledger | Control-plane dashboard (optional) | Plugin-based | Transforms/plugins | Promising; verify license/source before adoption |
| **microsoft/mcp-gateway** | github.com/microsoft/mcp-gateway | MIT | (K8s-oriented) | ~850 | Session-aware HTTP | Yes | Authz | K8s routing | Ops-focused | React portal (K8s) | K8s secrets | Limited LLM filters | **Poor** for single Ubuntu desktop (K8s-first) |
| **sparfenyuk/mcp-proxy** | github.com/sparfenyuk/mcp-proxy | MIT | Python | ~2.8k | **Bridge only** | Single server | Optional tokens | No | Basic | No | No | No | Glue only |

\*Stars approximate from WebFetch at research time.

### Short notes per top pick

**ContextForge** — Best OSS match for GUI + plugins + auth toggle + multi-transport. Covers reqs 1, 4 (partial secrets), 5 (via plugins), 6. Gaps: agent→MCP-server allowlists need custom RBAC/OPA plugin wiring; audit “metadata vs full payload → directory” needs custom sink; secrets GUI ≠ Infisical/Vault product.

**agentgateway** — Best performance/governance data plane; standalone mode fits Grinch. Covers 1, 2 (CEL/MCP authz), 5 (guardrails), UI. Gaps: audit-directory dual mode; rich secrets management; may be heavier than needed for “one machine.”

**ToolHive** — Strong security narrative (containers, audit, IdP). Covers 1, 2, 3 (stdout audit → redirect to dir), 4 (UI), isolation. Gaps: Docker dependency; response PI filters not primary; policy model may be registry/group oriented vs agent principal.

**MetaMCP** — Best DX for “compose namespaces + API keys + UI.” Gaps: maintenance note from author; middleware for PI/audit immature; Postgres required.

**joshrotenberg/mcp-proxy** — Best “thin Rust traffic plane” to embed under a custom control plane. Gaps: low stars; no full GUI/secrets/PI.

**MikkoParkkola** — Feature-rich (poisoning scan, identity propagation, dashboard) but **PolyForm Noncommercial** — unsuitable if Secure MCP Gateway will be commercial or redistributed commercially without a paid license.

---

## 3. Best-of-breed OSS (not necessarily MCP-native)

### B) Auth / identity for MCP

| Component | Role | Notes |
|-----------|------|-------|
| MCP OAuth 2.1 (spec) | Server-side protected resource | Hermes supports `auth: oauth` on `url` servers |
| JWT/JWKS at gateway | Client→gateway auth | ContextForge, agentgateway, joshrotenberg |
| RFC 8693 token exchange | Gateway→backend user identity | agentgateway/Solo docs; MikkoParkkola ADR-007; **do not** passthrough user tokens (confused deputy) |
| Better Auth / Keycloak / Auth0 | IdP | MetaMCP OIDC; ContextForge SSO |

**Speculation:** For Hermes + local agents, simplest toggle is gateway API key / JWT with `AUTH_REQUIRED=false` on loopback.

### C) Policy engines (agent → tool/server allowlists)

| Engine | License | Embed style | Fit for Agent A→server X |
|--------|---------|-------------|---------------------------|
| **Cedar** | Apache-2.0 | Rust native; cedar-go; used by MCPG/cMCP patterns | Excellent for explicit allowlists; analyzable |
| **OPA/Rego** | Apache-2.0 | Sidecar or Go/WASM | Best for complex rules + external data; ContextForge has OPA plugin |
| **Casbin** | Apache-2.0 | Go/Python/Rust libs | Simple RBAC/ABAC; low ops |
| **Cerbos** | Apache-2.0 | Sidecar PDP (+ Hub ePDP WASM for JS) | YAML/CEL policies; good DX; extra process |
| **OpenFGA** | Apache-2.0 | Server + SDKs | ReBAC; docs for MCP `tool#can_call`; model **agent as principal** |

**Recommendation for Grinch:** Start with **Casbin or Cedar embedded** in the control plane for agent→server→tool tuples; add OpenFGA only if relationship graphs grow.

### D) Audit / logging

| Stack | Fit |
|-------|-----|
| **JSONL files** in `~/audit/mcp/` (custom) | Matches requirement exactly (metadata vs full payload modes) |
| **ToolHive audit events** | Schema reference (`mcp_tool_call`, outcome denied/success); stdout — redirect/ship |
| **OpenTelemetry** (OTLP) → local collector | ContextForge/agentgateway native |
| **Fluent Bit** → file or Loki | SIEM-lite local |
| **MCPG audit ledger** | Tamper-evident (if adopting MCPG) |

**Gap:** Dual-mode “metadata-only OR metadata+full payload,” retention/delete in GUI, and writing **policy violations** to a dedicated audit **directory** is almost always **custom**.

### E) Secrets (local)

| Tool | License | Local Ubuntu | GUI | Notes |
|------|---------|--------------|-----|-------|
| **SOPS + age** | MPL/BSD | Excellent | No | Git-friendly; lowest ops |
| **Infisical** | MIT core (+ EE) | Docker/native | **Yes** | Best OSS secrets GUI; Postgres/Redis |
| **OpenBao** | MPL-2.0 | Yes | UI | Vault-compatible; heavier |
| **HashiCorp Vault** | BUSL | Yes | UI | ContextForge has Vault OAuth backend; license nuance |
| **pass / age CLI** | GPL/BSD | Excellent | No | Single-user |
| **1Password SDK** | Proprietary SaaS | SDK only | Cloud | No self-hosted vault |

**Recommendation:** SOPS+age for gateway config secrets; optional Infisical if GUI secrets management is mandatory.

### F) Prompt-injection / response filters

| Tool | License | Status | MCP wrap fit |
|------|---------|--------|--------------|
| **NeMo Guardrails** | Apache-2.0 | Active (~7k★) | Execution/output rails; Colang learning curve |
| **LlamaFirewall** (PurpleLlama) | Meta OSS | Active | PromptGuard + AlignmentCheck; agent-oriented |
| **LLM Guard** | MIT | **Archived ~2026-07** (per secondary sources); still usable as frozen fork | Input/output scanners; do not rely on updates |
| **Rebuff** | OSS | Prototype; needs OpenAI/Pinecone-ish stack | Narrow PI detection |
| **Invariant mcp-scan** | OSS | Tool-description poisoning / rug-pull scan | **Pre-admission** of servers, not runtime response filter |
| **agentgateway guardrails** | Apache-2.0 | Built-in | Regex + cloud moderations + webhooks |
| **ContextForge plugins** | Apache-2.0 | PII, content mod, external LlamaGuard | Best hook points (`tool_post_invoke`) |

**Recommendation:** Runtime filter = ContextForge plugin **or** custom middleware calling LlamaFirewall/NeMo on `tools/call` **results**; admission = mcp-scan / MikkoParkkola poisoning validator patterns.

### G) GUI frameworks / admin UIs

| Option | Notes |
|--------|-------|
| ContextForge Admin UI | Closest ready-made MCP admin (servers, tokens, logs) |
| MetaMCP UI | Namespaces, endpoints, inspector |
| agentgateway UI | Config + developer portal |
| ToolHive Studio | Desktop MCP management |
| Custom | **FastAPI + HTMX/Alpine** (ContextForge pattern) or **Next.js** (MetaMCP) or **Tauri** for local-only |

No mature OSS GUI was found that fully covers **policy editor + audit review/delete + MCP server CRUD + secrets** in one pane without customization.

---

## 4. Clear gaps requiring custom code

Even if ContextForge or agentgateway is the base:

1. **Agent-principal policy model** — “Hermes/Agent A → MCP server X allow; Agent B deny” with toggleable enforcement; map Hermes tool names (`mcp__…`) ↔ gateway namespaces.
2. **Audit directory writer** — dual mode (metadata | metadata+payload), policy-violation events, GUI list/delete, retention.
3. **Secrets management UX** — if Infisical/OpenBao not adopted: CRUD for API keys/credentials used when spawning stdio backends / injecting HTTP headers.
4. **Response filter pipeline** — wrap `tools/call` results (and optionally `resources/read`) with PI/PII scanners; quarantine or redact; log decisions.
5. **Auth toggle** — single config flag that leaves loopback open for Hermes while allowing lock-down for remote agents (most gateways have pieces; unify UX).
6. **Hermes-first packaging** — sample `config.yaml` snippets; optional stdio wrapper process; document Streamable HTTP vs SSE for Hermes `url`/`transport`.
7. **Control-plane ↔ data-plane split** (if not using a platform) — policy/GUI process + fast proxy (Rust/Go).

**What you can largely reuse:** MCP transport/aggregation (pick one gateway), OIDC/JWT, OPA/Cedar/Casbin, SOPS/Infisical, OTel/Fluent Bit, NeMo/LlamaFirewall as libraries.

---

## 5. Viability verdict

### **Viable with caveats**

**Reasons it is viable**
- Multiple mature OSS MCP gateways cover multi-server routing, stdio+HTTP, and auth (ContextForge, agentgateway, ToolHive, MetaMCP).
- Policy engines (Cedar/OPA/Casbin/OpenFGA) and filter libraries exist and are documented for MCP-like allowlists.
- Hermes already speaks both stdio and HTTP MCP and can sit behind a gateway with minimal client changes.

**Caveats**
1. **No turnkey product** matches all six requirements; expect a **composed architecture** + custom control plane (audit modes, agent policies, secrets GUI, filter orchestration).
2. **License watch:** MikkoParkkola/mcp-gateway is PolyForm-NC; Vault BUSL; Infisical EE features; prefer Apache/MIT cores for a redistributable Secure MCP Gateway.
3. **Ops weight:** Full ContextForge/MetaMCP/ToolHive stacks want Postgres/Redis/Docker — fine on Grinch, heavier than a single binary.
4. **Protocol churn:** Support newline stdio + Streamable HTTP; treat Content-Length framing and legacy SSE as compatibility shims only.
5. **Filter efficacy:** Prompt-injection detection is probabilistic; pair with **default-deny tool allowlists** (policy), not filters alone.

**Not “not viable”** — the ecosystem is sufficient to build; it is not a single `docker compose up` for the full security story.

### Suggested reference architecture (factual composition, not a product claim)

```
Hermes / agents  --stdio or HTTP-->  [Data plane: agentgateway OR ContextForge OR mcp-proxy]
                                         |  auth toggle, route, aggregate
                                         +--> Policy PDP (Cedar/Casbin/OPA): agent × server × tool
                                         +--> Filter (LlamaFirewall/NeMo/plugin) on responses
                                         +--> Audit sink → ~/secure-mcp/audit/{meta|full}/
                                         +--> Secrets (SOPS file or Infisical) for backend env/headers
                         Admin GUI (extend ContextForge UI or thin custom) --> same control APIs
```

---

## 6. Language trade study sketch (custom control plane)

| Criterion | **Go** | **Rust** | **Python** | **TypeScript** |
|-----------|--------|----------|------------|----------------|
| Fast local proxy | Excellent (stdlib HTTP, low RSS) | Best latency/throughput | Adequate; GIL/async OK for local | Good with Node; higher RSS |
| MCP SDK maturity | Growing; ToolHive/Docker in Go | Strong (rmcp, tower-mcp, agentgateway) | **Best** (official SDK, FastMCP, ContextForge) | Strong official TS SDK; MetaMCP |
| Policy embed | Casbin, cedar-go, OPA SDK | Cedar native, Casbin-RS | OPA REST, Casbin-Py, cedarpy | Casbin.js; call out to PDP |
| GUI | Separate (HTMX via templates or embed React) | Embed UI (agentgateway/MikkoParkkola pattern) | FastAPI+HTMX (ContextForge) | **Best** Next.js admin |
| Secrets/filter libs | Good | Good | **Best** (NeMo, LLM Guard, LlamaFirewall) | Medium (call Python sidecar) |
| Single-binary distribute | Excellent | Excellent | Needs venv/uvx/containers | Needs Node or bundled |
| Team velocity for glue | High | Medium | **Highest** for AI security glue | High for UI |
| Fit recommendation | Data plane + policy if Go-centric | Data plane if max efficiency | Control plane + filters + plugins | Admin UI only / MetaMCP fork |

**Sketch recommendation**
- **Data plane:** Rust (**agentgateway** as upstream or **joshrotenberg/mcp-proxy**) **or** adopt **ContextForge** wholesale if accepting Python.
- **Control plane + filters + audit writers:** **Python** (FastAPI) for speed of integration with NeMo/LlamaFirewall and Hermetic ops scripts.
- **Admin UI:** TypeScript (Next) **or** HTMX in the Python app.
- **Avoid** rewriting MCP framing in a fourth language; wrap an existing gateway.

If forced to one language for the whole Secure MCP Gateway: **TypeScript** (MetaMCP fork + custom middleware) for fastest full-stack, **or Python** (ContextForge fork/plugins) for security plugins — with the caveat Python is weaker as an ultra-lean always-on proxy than Rust/Go.

---

## Appendix A — Category cheat sheet

| Cat | Promising projects |
|-----|-------------------|
| A Gateways | ContextForge, agentgateway, ToolHive, MetaMCP, joshrotenberg/mcp-proxy, Docker mcp-gateway, MikkoParkkola (NC license), MCPG, microsoft/mcp-gateway (K8s) |
| B Auth | MCP OAuth 2.1, JWT/JWKS, RFC 8693 exchange, Keycloak/Auth0, Better Auth |
| C Policy | Cedar, OPA, Casbin, Cerbos, OpenFGA |
| D Audit | JSONL custom, ToolHive audit schema, OTel, Fluent Bit, MCPG ledger |
| E Secrets | SOPS+age, Infisical, OpenBao, pass, 1Password SDK (hosted) |
| F Filters | NeMo Guardrails, LlamaFirewall, ContextForge plugins, agentgateway guardrails, mcp-scan (admission), LLM Guard (archived) |
| G GUI | ContextForge Admin, MetaMCP, agentgateway UI, ToolHive Studio, custom HTMX/Next |

## Appendix B — Hermes wiring examples (illustrative)

```yaml
# HTTP to local gateway (preferred for shared Secure MCP Gateway)
mcp_servers:
  secure_gw:
    url: "http://127.0.0.1:8080/mcp"
    headers:
      Authorization: "Bearer ${SECURE_MCP_TOKEN}"
    # auth off on gateway => omit headers

# Stdio wrapper (if gateway exposes stdio client mode)
mcp_servers:
  secure_gw:
    command: "mcp-proxy"   # or contextforge wrapper / custom
    args: ["--transport", "streamablehttp", "http://127.0.0.1:8080/mcp"]
    env:
      API_ACCESS_TOKEN: "${SECURE_MCP_TOKEN}"
```

---

## Sources (primary)

- modelcontextprotocol.io transports (2025-11-25)
- ibm.github.io/mcp-context-forge (security features, plugins)
- agentgateway.dev docs; github.com/agentgateway/agentgateway
- github.com/metatool-ai/metamcp; github.com/stacklok/toolhive
- github.com/joshrotenberg/mcp-proxy; github.com/MikkoParkkola/mcp-gateway
- github.com/docker/mcp-gateway; github.com/sparfenyuk/mcp-proxy
- mcpg.dev docs; openfga.dev MCP authorization
- hermes-agent.nousresearch.com MCP config reference
- docs.stacklok.com ToolHive audit logging
- GitHub: protectai/llm-guard, NVIDIA NeMo-Guardrails, meta-llama PurpleLlama/LlamaFirewall, invariantlabs-ai/mcp-scan

