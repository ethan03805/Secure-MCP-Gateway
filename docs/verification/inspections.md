# Inspection and analysis records

Records for requirements whose SRS verification method is Inspection, Analysis or Demonstration (SRS Section 2.6). Each record follows the field table of [README.md](README.md). `tools/reqreport` counts a record as verification of a requirement when every field is filled in, the method equals the requirement's SRS method, every cited evidence file exists, and the record with the latest date for that requirement has result `pass`.

Line numbers in evidence references are those of the commit named in the record. Requirements that were inspected and found not met are listed in [gap-list.md](gap-list.md) instead of here.

## FR-10.37 Parameter Catalog content

| Field | Content |
|---|---|
| Requirement or scenario | FR-10.37 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Not profile-specific; darwin/arm64 |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: ran `python3 -I srs_build/gen.py . <out>` (the `make srs-check` build that CI runs) and read its parameter-catalog check and the generated catalog row.

Observations:

- `srs_build/gen.py:144` lists the eleven attributes the requirement names (ID, name, description, unit, data type, source element, capture point, derivation, sensitivity class, baselinable flag, cost class) and `srs_build/gen.py:149` fails the build for any entry missing one of them.
- `srs_build/gen.py:159` fails the build for any ARCH §10.3 `P-nnn` ID absent from the catalog; `srs_build/gen.py:157` rejects duplicate IDs.
- The build printed `OK: 558 requirements` with no warnings, and the generated SRS states "92 parameters; all 92 ARCH §10.3 IDs present" (`srs_build/gen.py:351`).
- `docs/parameters.json:1` carries `catalogVersion`, so the catalog is versioned.

Deviation: none.

## FR-12.11 No paid database features

| Field | Content |
|---|---|
| Requirement or scenario | FR-12.11 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Enforced and Standalone; source and CI configuration |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the database components the Data Server uses, the configuration the Gateway applies to them and the database installation used by CI.

Observations:

- Graph engine: Neo4j Community Edition 2026.05.0 (GPL-3.0), documented in `docs/graph.md:9`; the CI graph job runs the `neo4j:2026.05.0-community` image (`.github/workflows/ci.yml:287`).
- The schema migrations use only uniqueness constraints (`internal/graph/templates/0001_constraints.cypher:3`), which Community Edition supports. No property-existence or node-key constraints, roles, privileges, multiple databases, APOC or GDS procedures appear in `internal/graph` (searched for `IS NOT NULL`, `NODE KEY`, `CREATE ROLE`, `GRANT`, `CREATE DATABASE`, `apoc`, `gds.`).
- The Data Access Service connects over Bolt to a self-hosted engine on loopback (`internal/graph/backend.go:29`); there is no Aura or other hosted endpoint.
- Observation Store: DuckDB (MIT), embedded through `github.com/duckdb/duckdb-go/v2` (`go.mod:46`), or JSON Lines files.

Deviation: the Gateway does not query the engine's edition at start; an operator who installs Enterprise Edition would not be warned. No Enterprise feature is used either way.

## FR-18.2 Security Limitations

| Field | Content |
|---|---|
| Requirement or scenario | FR-18.2 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Documentation; not platform-specific |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: read `docs/security-limitations.md` against each limitation the requirement lists.

Observations (each item is stated with its consequence and, where one exists, a mitigation):

| Listed limitation | Where |
|---|---|
| The Standalone profile contains no server | `docs/security-limitations.md:11` (section 1) |
| In the Standalone profile the agent runs as the Gateway's identity | `docs/security-limitations.md:18` (section 2) |
| An agent's non-MCP native tools bypass the Gateway | `docs/security-limitations.md:24` (section 3) |
| Lockdown profiles are only as strong as each client's settings enforcement | `docs/security-limitations.md:30` (section 4) |
| A tunnel provider can read remote traffic | `docs/security-limitations.md:36` (section 5) |
| Running the Gateway inside a vendor's agent machine is not a control | `docs/security-limitations.md:42` (section 6) |
| Detection filters have measured false-positive and false-negative rates | `docs/security-limitations.md:46` (section 7) |
| Injection findings are tags only | `docs/security-limitations.md:50` (section 8) |
| Remote backends, resources and prompts are not supported | `docs/security-limitations.md:62` (section 11) |

Deviation: section 11 also says sampling, elicitation and roots are refused; southbound, the dispatcher currently declares the SDK's default `roots` capability (see SR-5.6-2 in [gap-list.md](gap-list.md)). This does not affect the items FR-18.2 lists.

## FR-19.2 Hostile suite results

| Field | Content |
|---|---|
| Requirement or scenario | FR-19.2 |
| Commit | `9e29ef00dcc41fd9be4a0293e2f0547eda280ab1` |
| Profile and platform | Standalone and Enforced (CI hostile job, ubuntu-latest) |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: fetched the status data published from the main-branch CI run of the commit above (`site-data` branch, `status.json`, generated 2026-10-17T03:02:06Z) and compared its `hostile` array with SRS Appendix L.

Observations:

- The `hostile` array has 27 entries, one for each Appendix L row HF-01 to HF-27 (`srs_build/appendix2.md` lists 27 `HF-` rows); each fixture ID appears exactly once.
- Every entry has non-empty `fixture`, `attack`, `expected`, `observed` and `pass` fields (20 entries pass, 7 do not; FR-19.2 requires publication, not passing).
- The CI hostile job produces `build/hostile.json` (`.github/workflows/ci.yml:324`) and `tools/reqreport` copies it into the status data (`tools/reqreport/main.go:119`).

Deviation: none.

## SR-1.12-1 No semantic authorization

| Field | Content |
|---|---|
| Requirement or scenario | SR-1.12-1 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Not profile-specific; source inspection |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected every input of the permit and route decision.

Observations:

- `policy.Request` (`internal/policy/policy.go:409`) holds only principal, session, framework profile, template, server, tool, and the manifest's side-effect class and source trust. It has no field for text, scores, embeddings or model output.
- `Decider.Decide` (`internal/policy/policy.go:550`) reads only that request, the compiled snapshot, the rate and quota counters and the session taint mark; the route is the request's server (`dec.Route = req.Server`).
- The only production caller builds the request from the authenticated session and the registry's tool reference (`internal/edge/pipeline.go:102`); `policy.Simulate` replays recorded requests of the same type (`internal/policy/simulate.go:200`).
- Filter findings and anomaly scores are produced after the decision by the request filter chain (`internal/analytics/service.go:178` registers the anomaly probe as a request filter) and can only block, add approval or withhold; they never produce a permit or select a route.

Deviation: none.

## SR-2.9-3 Loopback binding

| Field | Content |
|---|---|
| Requirement or scenario | SR-2.9-3 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Enforced and Standalone; default configuration, source inspection |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the default listener addresses and every place the daemon opens a TCP listener (`net.Listen` in `internal` and `cmd`).

Observations:

- Defaults: harness listener `127.0.0.1:8443` (`internal/config/config.go:393`), admin listener `127.0.0.1:8444` (`internal/config/config.go:408`), remote listener `127.0.0.1:8445` when the admin port is taken (`internal/config/remote.go:65`).
- Harness listener: `Gateway.Listen` refuses a non-loopback address before binding (`internal/edge/edge.go:314`, check at `internal/edge/edge.go:277`).
- Management Console and Control API (one admin listener): `adminapi.Server.Listen` applies the same check (`internal/adminapi/adminapi.go:481`).
- Remote Access listener: configuration validation refuses a non-loopback `remote.address` (`internal/config/remote.go:122`, called from `internal/config/config.go:523`), and the listener binds only that address (`internal/remote/remote.go:337`).
- The other TCP listeners are the loopback-checked metrics listener (`internal/metrics/metrics.go:267`) and the Egress Broker's per-instance proxies (`internal/egress/egress.go:280`), which are not harness or console listeners.

Deviation: the check accepts the host name `localhost` without resolving it.

## SR-4.13-1 Exclusive-gateway label

| Field | Content |
|---|---|
| Requirement or scenario | SR-4.13-1 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Documentation and matrix data |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: read `docs/clients/matrix.json` and the latest matrix results recorded in it.

Observations:

- All ten clients in `docs/clients/matrix.json:1` carry `"label": "gateway-available"`; no client is labelled `exclusive-gateway`. With no `exclusive-gateway` label, there is no client whose bypass results need checking, and every other client is marked `gateway-available` as the requirement states.
- `docs/security-limitations.md:34` states the same rule for operators.

Deviation: the result depends on the current data: no client has yet passed the FR-15.1 and SR-4.9-1 bypass tests. A record must be repeated when any client is relabelled.

## SR-5.7-3 No result caching

| Field | Content |
|---|---|
| Requirement or scenario | SR-5.7-3 |
| Commit | `067ccbc9f3ee086e986a154917e815b62960f23b` |
| Profile and platform | Not profile-specific; source inspection |
| Date | 2026-10-16 |
| Executor | Claude Code agent (requirement coverage task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the dispatch path, the response chain and the release path for any store of `tools/call` results.

Observations:

- `Registry.Call` (`internal/backend/backend.go:416`) spends a one-use launch capability and sends every call to the backend (`internal/backend/backend.go:449`); it returns the result to its caller and keeps no reference to it.
- The edge pipeline holds the result in local variables of one call's handler, runs the response filters on it and releases it after committing the delivered event (`internal/edge/pipeline.go:316`); nothing is stored on the `Gateway` or session structures.
- The only caches in `internal/edge`, `internal/backend` and `internal/pipeline` are the per-session tool catalogs and compiled input schemas (`internal/pipeline/filters.go:357`); neither holds results. The `ttlMs` cache hints apply to `server/discover` and `tools/list` only.
- Optional payload capture by the Observation Collector writes evidence copies for analysis; they are never returned to a request.

Deviation: none.

## SR-7.1-1 No side effects in retryable transactions

| Field | Content |
|---|---|
| Requirement or scenario | SR-7.1-1 |
| Commit | `a84aef79d8670572f206db22563941abb3b0bf47` |
| Profile and platform | Not profile-specific; source inspection |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification task) |
| Method | Inspection |
| Result | pass |

Steps: searched the module for the Neo4j driver and for every way to open a database transaction (`ExecuteWrite`, `ExecuteRead`, `BeginTransaction`, `database/sql` `Begin` and `BeginTx`), then read each transaction function and everything it calls.

Observations:

- Only `internal/graph/backend.go` imports the Neo4j driver. It opens retryable transaction functions in two places: `Neo4j.Write` (`internal/graph/backend.go:88`) and `Neo4j.Read` (`internal/graph/backend.go:109`).
- The write function loops over the prepared statements and calls `runTx`; the read function calls `runTx` once. `runTx` (`internal/graph/backend.go:118`) calls only `tx.Run`, `Result.Collect` and `Record.AsMap`, and `driverParams` (`internal/graph/backend.go:58`) only converts parameter maps and slices. No dispatch, egress, file, export, logging or channel operation occurs inside either function; results are returned to the caller, which acts on them after the transaction ends.
- The Data Access Service reaches the engine only through these two functions: `DAS.write` (`internal/graph/das.go:60`) checks the statement modes and calls `Backend.Write` outside any transaction.
- The Observation Store (DuckDB) uses `database/sql` with single statements (`internal/obsstore/duckdb.go:87`) and opens no transaction; nothing in the module calls `Begin` or `BeginTx`, so no other retryable transaction function exists.
- `TestTransactionFunctionsHoldOnlyDatabaseWork` (`internal/graph/catalog_test.go:159`) parses `backend.go` and fails when a transaction function calls anything outside that set, so a later change to these two functions is caught.

Deviation: none.

## FR-8.35 Console visual rules

| Field | Content |
|---|---|
| Requirement or scenario | FR-8.35 |
| Commit | `1391541c07403092c5818faf132c97bfde4f4577` |
| Profile and platform | Standalone; darwin/arm64, Chromium, Firefox and WebKit of Playwright 1.64.1 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (verification task) |
| Method | Inspection |
| Result | pass |

Steps: inspected the 24 view paths of `console/e2e/style.spec.ts:12` (G-01 to G-14 and the Egress, Runtime, Remote access, library, draft, filter workbench, investigation graph and new-campaign pages) against each rule of the checklist in `docs/console-style.md:5`, in the light and the dark color scheme. The measurable rules were checked by `console/e2e/style.spec.ts:40`, which opens every disclosure of each view and reads the rendered page; the other rules were checked by reading the source and the rendered views.

Observations, by checklist rule:

- Lists are tables: every collection is rendered by `DataTable` (`console/src/ui.tsx:205`), a `<table>` with a header row whose sortable columns are buttons with `aria-sort`. The test found the nine G-04 parameter catalog tables without sortable headers; they were changed to `DataTable` before this record. Four tables list a fixed enumeration in a meaningful order rather than a collection of records (the G-01 first-run steps, the two G-06 band tables, the G-03 mandatory audit floor) and have no sort; the test names them as exemptions. No card grid exists.
- One typeface family: text is IBM Plex Sans and IDs, digests and code are IBM Plex Mono (`console/src/styles.css:37`, `console/src/styles.css:38`), bundled from `@fontsource` (`console/package.json:13`). Every visible text node of every view uses one of the two faces at 12, 13, 14, 16 or 20 px.
- No decoration: no element has a gradient background or a drop shadow; the one box shadow is an inset 3 px bar that marks a refused row next to its outcome text (`console/src/styles.css:573`). No emoji appear. The only glyph icons are the sort marks, which are `aria-hidden` next to the column label, and the state marks, which sit next to a text label.
- Color carries state only: state is shown by `StateLabel` (`console/src/ui.tsx:85`), which always renders the state word next to its colored mark.
- Density: every table row whose cells hold one line is at most 32 px high.
- Text: no exclamation mark appears in headings, labels, buttons, table headers or paragraphs. Error states show the control API status, message and reason code (`console/src/ui.tsx:130`).
- Hand-built components: the console's runtime dependencies are React, React DOM and the two font packages (`console/package.json:12`); there is no component kit.
- Accessibility: see `FR-8.32.md` and `console/e2e/a11y.spec.ts:38`.
- Local assets: the console page loads scripts, styles and fonts only from the Gateway under a strict content security policy (`console/e2e/console.spec.ts:150`).

Deviation: the four fixed-enumeration tables are not sortable. Sorting them would remove meaning, because their order is the order of the steps or bands.

## FR-2.1 Principal registry

| Field | Content |
|---|---|
| Requirement or scenario | FR-2.1 |
| Commit | `e8b6606a426d0d209e1fa5a461cbdeb38fa7f85d` |
| Profile and platform | Not profile-specific; darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (gap implementation task) |
| Method | Inspection |
| Result | pass |

Steps: ran `go test ./internal/principals -run TestRoutes -v`, which creates principal `agent` through `POST /api/v1/principals` (the G-11 route), issues it a credential through `POST /api/v1/principals/agent/credentials`, suspends and re-enables it, and lists it through `GET /api/v1/principals`. Then ran the same Directory calls the routes make (`AddPrincipal`, `Issue`, `SetSuspended`) in a scratch test and read the stored file `state/principals.json` and the listed view.

Observations:

- The stored principal record (`internal/principals/principals.go:70`) holds `id`, `framework`, `display_name` and `profile` (the Framework Profile ID), with `created_by` and `created_at`; the route fills them from the request (`internal/principals/http.go:142`).
- Credentials are stored with a reference to their principal (`internal/principals/principals.go:80`, member `principal`), and the principal's view lists its credential references with client ID, redirect URIs and revocation state, never the secret hash (`internal/principals/principals.go:333`, `internal/principals/principals.go:359`).
- The enabled state is the absence of an entry in the suspension map (`internal/principals/principals.go:102`); the view reports `enabled` and the suspension's actor, time and reason. Principals of the configuration file appear in the same view with `source: "file"` and their `enabled` value (`internal/principals/principals.go:386`).
- The scratch run stored `{"id": "agent", "framework": "codex", "display_name": "Agent", "profile": "dev", ...}`, a credential with `"principal": "agent"`, and `"suspended": {"agent": {"by": "admin:admin", ...}}`; the view showed `"enabled": false` with the suspension and the credential.

Deviation: none.


## FR-7.7 Local certificate authorities

| Field | Content |
|---|---|
| Requirement or scenario | FR-7.7 |
| Commit | `5e43a626323809132161cb9fb85bab8c6d71d5a8` |
| Profile and platform | Standalone; darwin/arm64 |
| Date | 2026-10-17 |
| Executor | Claude Code agent (console gap task) |
| Method | Inspection |
| Result | pass |

The statement inspected is the release 1.0 form of FR-7.7 (one server CA; the client CA is deferred with the mTLS Harness Profile as FR-7.15).

Steps: bootstrapped an instance with `smcpctl bootstrap` (the Playwright acceptance setup, `console/e2e/gateway.ts`), ran `openssl x509 -noout -text` on `state/tls/ca.crt` and `state/tls/server.crt`, read the key inventory code, and searched the source for every use of the CA key file and every certificate the Gateway signs.

Observations:

- The CA certificate is `CN=Secure MCP Gateway server CA`, `CA:TRUE, pathlen:0`, key usage `Certificate Sign, CRL Sign, Digital Signature`, with critical name constraints permitting only the listener names (`DNS:localhost` here) (`internal/keys/keys.go:169`, `internal/keys/keys.go:183`).
- The issued listener certificate has issuer `Secure MCP Gateway server CA`, key usage `Digital Signature` and extended key usage `TLS Web Server Authentication` only (`internal/keys/keys.go:266`, `internal/keys/keys.go:267`).
- The Gateway signs exactly two kinds of certificate: the self-signed CA (`internal/keys/keys.go:188`) and the listener certificate (`internal/keys/keys.go:271`). The CA key file is loaded only to issue or renew the listener certificate (`internal/keys/keys.go:337`, `internal/keys/rotate.go:151`); no other package opens it (the only other reference is the list of key files that `smcpctl bootstrap` refuses to overwrite, `cmd/smcpctl/bootstrap.go:233`).
- The key inventory names one file per purpose, with `server_ca` mapped to `tls/ca.key` and no other purpose sharing it (`internal/keys/rotate.go:460`).

Deviation: none for the release 1.0 statement. A separate client CA does not exist; it is FR-7.15, deferred.
