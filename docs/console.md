# Management console

The management console is the browser interface of the Management Console & Control API (E-24). It is built into `smcpd` and served on the admin listener; there is nothing to install separately and it loads nothing from the Internet (FR-8.26). Everything it does goes through the control API, so every action is authenticated, checked for origin and recorded in the evidence journal exactly as the same action from `smcpctl`. The routes it uses are documented in [api/console.md](api/console.md) and [api/approvals.md](api/approvals.md). Its visual rules are in [console-style.md](console-style.md).

## Opening the console

1. Start `smcpd`. The console is at the admin listener address in `smcp.toml` (`[admin_listener] address`), by default `https://127.0.0.1:8444/`. `smcpd` logs it at startup as `admin=`.
2. Open that exact address. Use the same host form as the configuration (`127.0.0.1`, not `localhost`, for the default): the control API refuses requests whose `Origin` differs from the configured admin URL, so sign-in fails from another host name with `origin_refused`.
3. The listener certificate is issued by the Gateway's local CA (`<state>/tls/ca.crt`). Until you trust that CA the browser shows a certificate warning. To trust it on macOS: `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <state>/tls/ca.crt`. The CA is name-constrained to loopback names, so trusting it does not let it vouch for other sites.

Approval links in harness error messages (`data.approvalUrl`) and in desktop notifications open the console at `/approvals/<id>`. Every view and every session, server, event and approval has its own path, and a path opened before sign-in opens after sign-in (FR-8.28).

## Signing in

| Account | Configured in | What it can open |
|---|---|---|
| Administrator | `[admin]` (`username`, `password_hash`), or the bootstrap token | Every view and action |
| Approver | `[[approvals.account]]` | Approvals (G-13) only: list, inspect, approve, deny |
| Session Approver | `[[approver]]` | Not the console. Session Approvers sign in on the Gateway's own OAuth page when a harness connects (FR-2.19) |

Choose the account kind on the sign-in page, then enter the username and password. A sign-in lasts 30 minutes; when it ends the console returns to the sign-in page and keeps the path you were on. **Sign out** ends the token on the Gateway at once.

First installation: when `smcpctl bootstrap` ran without `--admin-password-file`, it printed a one-use bootstrap token valid for 24 hours. On the sign-in page select **set the administrator password with a bootstrap token**, enter the token and a password of at least 12 characters, then sign in.

Failed sign-ins are rate limited per source and locked out per account with backoff, as for the control API; the error shows the reason code (`signin_failed`, `rate_limited` with the wait time, `busy`).

The token is kept in the tab's session storage and sent as a bearer header; it is not a cookie, so another site cannot make the browser use it. The page's Content-Security-Policy allows no inline or third-party script.

## Layout

- **Status bar** (top of every view): enforcement state (`healthy`, `degraded`, `fail-closed`, or `emergency stop`), profile and release label (`not enforced` in the Standalone profile, FR-13.10), active policy revision, active session count, whether live updates are connected, the **Emergency stop** or **Resume** button, the signed-in account and **Sign out**. In the fail-closed state the bar turns red.
- **Navigation** (left): the views the signed-in role may open, grouped by task, each with its view code. An Approver sees only Approvals.
- **Theme**: System, Light or Dark, kept per browser.

Each view has a **Help for this view** section. Lists are tables; select a column header (or focus it and press Enter) to sort by it, again to reverse.

## Views

| Code | View | Path | What it does | Backend |
|---|---|---|---|---|
| G-01 | Gateway control | `/` | Enforcement state and each health cause with its meaning, profile, policy revision, sessions, launcher, servers; **Reload policy**; journal verification; first-run checklist | `/admin/v1/health`, `/admin/v1/policy/reload`, `/api/v1/audit/verify` |
| G-11 | Sessions and principals | `/sessions`, `/sessions/<id>` | Active sessions; a session's binding (principal, client, template, purpose, approving Session Approver, deadlines); **Terminate session**; principals, OAuth clients and Session Approver accounts | `/api/v1/sessions*` |
| G-10 | Servers and library | `/servers`, `/servers/<alias>`, `/catalog` | Servers with state, revision, manifest source, protocol version and launcher; a server's argument vector, environment keys, secret slots, risk classes and tools with input schemas; the tool catalog per template with rule, approval and filters; signed packages when E-13 is installed | `/api/v1/servers*`, `/api/v1/catalog`, `/api/v1/packages` |
| G-13 | Approvals | `/approvals`, `/approvals/<id>` | Pending approvals with time left; other states; an approval's bound request (tool, revisions, argument digest, decisive rules, session) and its canonical arguments; **Approve this call** and **Deny this call** with an optional comment | `/api/v1/approvals*` |
| G-14 | Audit investigation | `/audit`, `/audit/events/<id>` | Journal verification; journal browser with filters and paging; **Export CSV** and **Export JSON Lines**; an event with links to its decision, call, session and principal, and every phase of the same call; the investigation graph when E-25/E-26 are installed | `/api/v1/audit/*`, `/api/v1/graph` |
| G-02 | Policy studio | `/policy` | Policy revisions | `/api/v1/policy` |
| G-03 | Audit profile tuning | `/audit-profiles` | Audit profiles | `/api/v1/policy/audit-profiles` |
| G-06 | Anomaly response | `/anomaly-response` | Sigma-band response policy | `/api/v1/anomalies/policy` |
| G-12 | Secrets | `/secrets` | Secret metadata (never values) | `/api/v1/secrets` |
| G-04 | Observation workbench | `/observations` | Parameter Catalog and observation policies | `/api/v1/observations/catalog`, `/api/v1/observations/policies` |
| G-05 | Behavior analytics | `/analytics` | Baselines and anomalies | `/api/v1/baselines`, `/api/v1/anomalies` |
| G-07 | Performance | `/performance` | Throughput and stage timing | `/api/v1/health/performance` |
| G-08 | Data server and memory | `/data-server` | Data server status and backups | `/api/v1/health/data`, `/api/v1/backup` |
| G-09 | Research campaigns | `/research` | Campaigns | `/api/v1/research/campaigns` |
| | Egress | `/egress` | Egress Broker state, grants and connections | `/api/v1/egress`, `/api/v1/egress/grants`, `/api/v1/egress/connections` |
| | Runtime | `/runtime` | Sandbox summary and instances | `/api/v1/runtime`, `/api/v1/runtime/instances` |
| | Remote access | `/remote` | Remote Access profile and client registrations | `/api/v1/remote`, `/api/v1/clients` |

The views from G-02 down read routes that belong to other elements. When this Gateway build does not serve the route, the view says **Not available in this build** and names the route. When the route exists, the view shows its records as a table of their fields, with each full record as text; editing those records is done with `smcpctl` until the console gains editors for them.

### Emergency stop

**Emergency stop** in the status bar opens a dialog that asks for a reason. **Stop the Gateway** refuses every tool call at once: no call is dispatched and no result of a call in flight is released (FR-4.14). The status bar then shows `emergency stop` and the Gateway health is `fail-closed` with cause `emergency_stop`. The stop is recorded with your account and the reason (`reason_code` `EMERGENCY_STOP`). **Resume** asks for confirmation and records `EMERGENCY_RESUME`. If the journal cannot record the stop, the Gateway still stops and the console shows the warning.

### Approving a held call

When a policy rule with `"approval": true` is used, the call is held and appears in Approvals within about a second, without reloading. Open it, check the arguments and the bound revisions, optionally add a comment, then **Approve this call** or **Deny this call**. An approval during the hold lets the held call continue; after the hold the harness has an error telling the person to approve and run the request again, and the approval is used by that retry. See [approvals.md](approvals.md).

### First-run checklist

Gateway control lists the setup steps of FR-8.31 and marks each from Gateway state:

| Item | Done when |
|---|---|
| Administrator created | You are signed in as the administrator |
| Session Approver created | At least one `[[approver]]` account exists |
| First server packaged and enabled | A running server's tools come from a verified package manifest |
| First policy revision published | A policy revision is active |
| First harness connected | A `session` event is in the journal, or a session is active |
| Approval tested | An approval has been approved or denied |
| Backup configured | The backup route reports a configured backup; `unknown` while backups are not available in this build |

### Journal browser and export

Filters match exact values (`class`, `outcome`, `reason_code`, `session_id`, `correlation_id`, `principal_id`, `decision_id`, `origin`), except **Text**, which matches any part of the event, and the time range in RFC 3339 (`2026-10-17T00:00:00Z`). The filter is part of the address, so a filtered list can be bookmarked. The search for a harness error is its `data.correlationId` in **Correlation ID** (see [troubleshooting.md](troubleshooting.md)).

Exports contain the events matching the current filter, oldest first, up to 100,000 events. Each export is recorded in the journal. In CSV a cell that begins with `=`, `+`, `-` or `@` is prefixed with an apostrophe so that spreadsheet programs show it as text. All journal content is shown as text in the console; nothing from an event is interpreted as markup.

**Verify the journal now** checks every closed segment's hash and signature, the chain between segments, the open segment and the anchor, and shows the result and any findings (for example a segment sealed by crash recovery). It is the same check as `smcpctl journal verify`.

## Live updates

While signed in as an Administrator, the console keeps an event stream open (`/api/v1/audit/stream`) and refreshes the open view when the journal records something, typically within a second (FR-8.23). Approvers use the approvals watch stream. The status bar shows `live`; if the stream drops it shows `not live: refresh to update` and reconnects with backoff.

## States and errors

Each view shows `Loading` while it reads, an empty state that says what would fill it, and on failure the control API message, HTTP status and reason code with **Retry** (FR-8.29). Common codes:

| Code | Meaning | What to do |
|---|---|---|
| `unauthenticated` | The sign-in ended or the token is unknown | Sign in again |
| `role_refused` | The account's role may not use this route | Sign in as an Administrator |
| `origin_refused` | The page was opened from a different address than the configured admin URL | Open the console at the address in `[admin_listener]` |
| `route_not_found` | This build does not serve the route | Shown as "Not available in this build" |
| `audit_unavailable` | The journal could not record the action, so it was not taken | Check disk space and `smcpctl health` |
| `journal_unreadable` | The journal files could not be read | Check the state directory permissions |
| `not_active` | The session ended before it could be terminated | None |
| `not_pending` | The approval was already decided, expired or used | Refresh the list |
| `export_too_large` | More than 100,000 events match | Narrow the filter |

## Keyboard and accessibility

Every action works with the keyboard. **Skip to content** is the first focusable element. Tab moves through the navigation, view controls and table headers; Enter or Space activates; Escape closes a dialog and returns focus. Focus is always visible. Moving to a view moves focus to its heading. State is never shown by color alone: each state has a word and a shape (square for good, diamond for degraded or warning, triangle for failure or refusal, ring for pending). Motion is limited to what the browser does natively and respects reduced-motion settings. The console is checked against WCAG 2.2 AA with axe-core in light and dark schemes in CI; automated checks do not cover every criterion.

Supported browsers (FR-8.30): current Chromium-based browsers, Firefox and Safari on macOS. CI runs the acceptance tests in Chromium only.

## Building the console

The sources are in `console/` (React, TypeScript, Vite; no component library). The build output in `console/dist` is committed and embedded into `smcpd` by `console/embed.go`, so building `smcpd` needs only Go.

| Command | What it does |
|---|---|
| `make console` | `npm ci` if needed, typecheck, and build `console/dist` |
| `make console-check` | Fails when the committed `console/dist` differs from a fresh build |
| `make console-e2e` | Builds `smcpd`, bootstraps a temporary instance in `console/.e2e`, and runs the Playwright acceptance and accessibility tests against it |
| `cd console && npm run dev` | Development server on `http://localhost:5173` proxying `/api` and `/admin` to `https://127.0.0.1:8444`; sign-in from the development server is refused by the origin check unless the admin listener is configured for it, so use it for layout work |

After changing anything under `console/src`, run `make console` and commit `console/dist` with the change. The CI job `console` fails when they differ.

## Not built yet

- Session suspension, principal and credential management, and client registration approval are not in G-11; principals and clients are edited in `smcp.toml`.
- G-10 has no enable, suspend, retire, alias or trust-anchor actions and shows no attestations, drift, SBOM, mounts or egress destinations; those come with E-13 and E-14.
- The G-02 to G-09 and G-12 views list records only; their editors (policy drafts, diff and simulation, workbench controls, analytics charts, campaign actions, write-only secret entry) need those elements' APIs.
- The console uses bearer tokens, not the cookie session with CSRF token and `If-Match` preconditions of SR-2.6-1 and SR-8.9-1.
- The Operator, Policy Author, Auditor and Researcher roles of Appendix C do not exist yet; the console knows Administrator and Approver.
- The journal browser reads the journal files on every request; it has no index, so large journals are slow to page (FR-11.8).
- Playwright tests do not yet feed the requirement report; their claims are annotations only.
