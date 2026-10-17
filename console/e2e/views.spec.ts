// One acceptance test per console view (FR-8.34) against the running
// Gateway of global-setup: each exercises the view's primary actions
// through the real control API. Where the element behind a view needs
// state this test Gateway cannot produce (the graph mirror without Neo4j,
// scored anomalies without a promoted baseline, remote registrations
// without a tunnel), the route is answered with a fixture and the test
// says so. Claims are annotations (see docs/console.md).
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { bin, mcpCall, work } from "./gateway";
import { claims, g, go, mock, nav, signIn } from "./helpers";

test.describe.configure({ mode: "serial" });

test("G-01 gateway control: health, monitor causes, verification and checklist", async ({ page }) => {
  claims("FR-8.3", "FR-8.31", "FR-7.12");
  await signIn(page, "/");
  await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Health monitor causes" })).toContainText("unconfined");
  await page.getByRole("button", { name: "Verify the journal now" }).click();
  await expect(page.getByText("verified", { exact: true }).first()).toBeVisible();
  const checklist = page.getByRole("table", { name: "First-run checklist" });
  await expect(checklist).toContainText("Administrator created");
  await expect(checklist).toContainText("Backup configured");
});

test("G-02 policy studio: draft, validate, diff, simulate, publish and roll back", async ({ page }) => {
  claims("FR-8.4", "FR-3.4", "FR-3.9");
  // A call in the journal for the simulation to replay (earlier tests made
  // others; a refused call is recorded as well).
  await mcpCall(g, "ref_echo", { text: "policy" }, { expect: "policy", timeout: "60s" }).done;
  await signIn(page, "/policy");
  await expect(page.getByRole("table", { name: "Policy revisions" })).toContainText("r1");
  await page.getByRole("link", { name: "Draft", exact: true }).click();
  // The draft takes the next free revision ID (r2 on a fresh Gateway).
  const revInput = page.getByLabel("Revision ID of the draft");
  await expect(revInput).toHaveValue(/^r\d+/);
  const rev = `e2e-${Date.now()}`;
  await revInput.fill(rev);
  // Structured editor: add a template with one rule.
  await page.getByLabel("New template name").fill("echo-only");
  await page.getByRole("button", { name: "Add", exact: true }).first().click();
  await page.getByRole("button", { name: "Add a rule to echo-only" }).click();
  const rule = page.getByRole("group", { name: "Rule rule-1" });
  await rule.getByLabel("Tools (space separated)").fill("echo");
  await rule.getByLabel("Rule ID").fill("echo-rule");
  // Offer it to the dev profile.
  await page.getByRole("group", { name: "Templates sessions of this profile may use" }).getByLabel("echo-only").check();
  await page.getByRole("button", { name: "Validate" }).click();
  await expect(page.getByText(new RegExp(`Valid: revision ${rev}`))).toBeVisible();
  await page.getByRole("button", { name: "Diff against the active revision" }).click();
  await expect(page.getByRole("table", { name: "Policy changes" })).toContainText("template_added");
  await page.getByRole("button", { name: "Simulate" }).click();
  await expect(page.getByText(/replayed from the/)).toBeVisible();
  await page.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByRole("heading", { level: 1, name: `Policy revision ${rev}` })).toBeVisible();
  await expect(page.getByText("active", { exact: true }).first()).toBeVisible();
  // Effective permissions of the new template.
  await page.getByLabel("Template").selectOption("echo-only");
  await expect(page.getByRole("table", { name: "Effective permissions of echo-only" })).toContainText("ref/echo");
  // Roll back to r1.
  await go(page, "/policy/revisions/r1");
  await page.getByRole("button", { name: "Roll back to this revision" }).click();
  await page.getByRole("dialog", { name: "Roll back to r1" }).getByRole("button", { name: "Roll back" }).click();
  await expect(page.getByRole("table", { name: "Policy revisions" })).toContainText(/r1-rb\d+/);
  await expect(page.getByTestId("status-strip")).toContainText(/policy r1-rb\d+/);
});

test("G-02 filter workbench: a redaction profile on synthetic text", async ({ page }) => {
  claims("FR-8.27");
  await signIn(page, "/policy/filters");
  await expect(page.getByRole("table", { name: "Rule sets" })).toContainText("pii");
  const filters = page.getByRole("group", { name: "Filters to run" });
  for (const id of ["size-limit", "output-schema", "content-type-gate", "secret-fingerprint", "unicode-control", "injection-marker", "delimit-untrusted"]) await filters.getByLabel(id).uncheck();
  await page.getByLabel("Result text").fill("Write to jane@example.com about it.");
  await page.getByRole("button", { name: "Run filters" }).click();
  await expect(page.getByRole("definition").filter({ hasText: "redact" })).toBeVisible();
  const runs = page.getByRole("table", { name: "Filter runs" });
  await expect(runs).toContainText("pii-detect");
  await expect(page.getByText("Transformed output")).toBeVisible();
  await expect(page.locator("figure.json pre").last()).not.toContainText("jane@example.com");
});

test("G-03 audit profile tuning: the floor is read-only and capture is edited", async ({ page }) => {
  claims("FR-8.5");
  await signIn(page, "/audit-profiles");
  const floor = page.getByRole("table", { name: "Mandatory audit floor" });
  await expect(floor).toContainText("auth_failure");
  await expect(floor.locator("input, select, textarea")).toHaveCount(0);
  await page.getByLabel("Normal-band sampling rate (0 to 1)").fill("0.5");
  await expect(page.getByText("sampling_rate = 0.5")).toBeVisible();
});

test("G-04 observation workbench: grouped catalog search, presets, cost and preview", async ({ page }) => {
  claims("FR-8.6", "FR-8.7", "FR-8.8", "FR-8.11", "FR-8.12");
  await signIn(page, "/observations");
  await page.getByLabel(/Search parameters/).fill("latency");
  await expect(page.getByRole("checkbox", { name: "Capture end_to_end_latency" })).toBeVisible();
  await expect(page.getByText(/^(dispatch|release|response-inspection|request-received|decision|periodic)/).first()).toBeVisible();
  await page.getByLabel(/Search parameters/).fill("");
  await page.getByRole("button", { name: "Performance profiling" }).click();
  await expect(page.getByText(/Applied preset Performance profiling/)).toBeVisible();
  await page.getByLabel("Save the selection as a preset").fill("my preset");
  await page.getByRole("button", { name: "Save preset" }).click();
  await expect(page.getByRole("button", { name: "my preset (saved)" })).toBeVisible();
  await expect(page.getByText("Bytes per captured record (estimate)")).toBeVisible();
  await page.getByRole("button", { name: "Show the configuration for this selection" }).click();
  await expect(page.getByText(/parameters = \[/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Live record preview" })).toBeVisible();
});

test("G-05 behavior analytics: snapshot, promotion, distributions and anomaly drill-down", async ({ page }) => {
  claims("FR-8.13");
  await signIn(page, "/analytics");
  await page.getByRole("button", { name: "Build a snapshot now" }).click();
  await expect(page.getByText(/Built snapshot/)).toBeVisible();
  await page.getByRole("table", { name: "Baseline snapshots" }).getByRole("button", { name: "Promote" }).first().click();
  await expect(page.getByText(/is promoted/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Feature distributions" })).toBeVisible();
  // Scored anomalies need a characterized baseline; a fixture stands in.
  const now = Date.now();
  await mock(page, "**/api/v1/anomalies?**", {
    count: 2,
    rows: [
      { ts: new Date(now - 60_000).toISOString(), correlation_id: "corr-elevated", snapshot_id: "s", context: "principal=cc|tool=read_file", combined: 2.4, contributing_feature: "request_bytes", band: "elevated", actions: '["alert"]', mode: "async" },
      { ts: new Date(now - 30_000).toISOString(), correlation_id: "corr-critical", snapshot_id: "s", context: "principal=cc|tool=read_file", combined: 6.2, contributing_feature: "request_bytes", band: "critical", actions: '["alert","capture_escalation"]', mode: "async" },
    ],
  });
  await page.reload();
  await expect(page.getByRole("img", { name: /z-score timeline/ })).toBeVisible();
  const table = page.getByRole("table", { name: "Abnormal events" });
  await expect(table).toContainText("critical");
  // Keyboard: focus the critical dot and open it with Enter.
  await page.getByRole("button", { name: /^critical 6.20/ }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/audit\?correlation_id=corr-critical/);
});

test("G-06 anomaly response: only restrict-only actions per band", async ({ page }) => {
  claims("FR-8.14");
  await signIn(page, "/anomaly-response");
  await expect(page.getByRole("table", { name: "Current response per band" })).toContainText("uncharacterized");
  const options = await page.getByLabel("critical action").locator("option").allTextContents();
  expect(options).toEqual(["Record and alert", "Alert and escalate capture", "Escalate and require approval", "Require approval and withhold the result"]);
  await page.getByLabel("critical action").selectOption("withhold");
  await page.getByLabel("abnormal action").selectOption("approve");
  await expect(page.getByText(/withhold_band = "critical"/)).toBeVisible();
  await expect(page.getByText(/require_approval_band = "abnormal"/)).toBeVisible();
  await expect(page.getByText(/scoring = "sync"/)).toBeVisible();
});

test("G-07 performance: throughput, overhead per revision and stage time", async ({ page }) => {
  claims("FR-8.15");
  const r = await mcpCall(g, "ref_echo", { text: "perf" }, { expect: "perf", timeout: "60s" }).done;
  expect(r.code, r.out).toBe(0);
  await signIn(page, "/performance");
  await expect(page.getByRole("heading", { name: "Gateway overhead per policy revision" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Time per stage and policy object" })).toBeVisible();
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
  await expect(page.getByRole("combobox", { name: "Policy revision" })).toBeVisible();
});

test("G-08 data server: graph state, store sizes, backup and keys", async ({ page }) => {
  claims("FR-8.16", "FR-17.6");
  await signIn(page, "/data-server");
  await expect(page.getByText("The graph mirror is disabled")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Observation Store" })).toBeVisible();
  await page.getByLabel("Passphrase").fill("console e2e backup passphrase");
  await page.getByRole("button", { name: "Take a backup now" }).click();
  await expect(page.getByText(/Backup written/)).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole("table", { name: "Backups" })).toContainText("ok");
  await expect(page.getByRole("term").filter({ hasText: "Listener certificate" })).toBeVisible();
});

test("G-09 research campaigns: create, submit, approve, export and dictionary", async ({ page }) => {
  claims("FR-8.17", "FR-8.9");
  await signIn(page, "/research");
  await page.getByRole("link", { name: "New campaign" }).click();
  await page.getByLabel("Name", { exact: true }).fill("console acceptance study");
  await page.getByLabel("Start (RFC 3339)").fill(new Date(Date.now() - 60_000).toISOString().replace(/\.\d{3}Z$/, "Z"));
  await page.getByRole("button", { name: "Create draft campaign" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Campaign console acceptance study" })).toBeVisible();
  await page.getByRole("button", { name: "Submit for approval" }).click();
  await expect(page.getByText("The campaign is now submitted.")).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText(/The campaign is now (approved|active)\./)).toBeVisible();
  // The campaign becomes active once its start time has passed.
  await expect(async () => {
    await page.reload();
    await expect(page.getByRole("definition").filter({ hasText: /^active$/ })).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 60_000 });
  await page.getByRole("button", { name: "Export", exact: true }).click();
  await expect(page.getByRole("table", { name: "Export files" })).toContainText("dictionary.json");
  await expect(page.getByRole("table", { name: "Data dictionary" })).toBeVisible();
  await go(page, "/research");
  await expect(page.getByRole("table", { name: "Dataset exports" })).toContainText("csv");
});

test("G-11 sessions and principals", async ({ page }) => {
  claims("FR-8.19");
  await signIn(page, "/sessions");
  await expect(page.getByRole("table", { name: "Principals" })).toContainText("claude-code-local");
  await expect(page.getByRole("heading", { name: "Active sessions" })).toBeVisible();
});

test("G-11 remote access: enable, disable and decide a client registration", async ({ page }) => {
  claims("FR-16.5", "FR-16.11");
  await signIn(page, "/remote");
  await page.getByLabel(/Public URL/).fill("https://gateway.example.ts.net");
  await page.getByRole("button", { name: "Enable remote access" }).click();
  await expect(page.getByText("enabled: reachable from outside this machine")).toBeVisible();
  await page.getByRole("button", { name: "Disable", exact: true }).click();
  await expect(page.getByRole("definition").filter({ hasText: /^disabled$/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Client registrations" })).toBeVisible();
  // A pending registration needs a client on the tunnel; a fixture stands in
  // for the list, and the approval request goes to the fixture as well.
  const pending = { client_id: "smcp-dcr-e2e", client_name: "Example agent", status: "pending", registration: "dynamic", redirect_uris: ["https://agent.example/cb"], registered_at: new Date().toISOString(), source_address: "203.0.113.7" };
  await mock(page, "**/api/v1/clients", { clients: [pending] });
  let approved: unknown = null;
  await page.route("**/api/v1/clients/smcp-dcr-e2e/approve", async (r) => {
    approved = r.request().postDataJSON();
    await r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...pending, status: "approved", principal: "claude-code-local" }) });
  });
  await page.reload();
  await page.getByRole("table", { name: "Client registrations" }).getByRole("button", { name: "Approve" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve Example agent" });
  await dialog.getByRole("combobox", { name: "Principal" }).selectOption("claude-code-local");
  await dialog.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("Example agent is approved and bound to claude-code-local.")).toBeVisible();
  expect(approved).toEqual({ principal: "claude-code-local" });
});

test("G-12 secrets: write-only create, rotate, impact and revoke", async ({ page }) => {
  claims("FR-8.20", "FR-6.2");
  const value = "e2e-secret-value-1234567890";
  const rotated = "e2e-rotated-value-0987654321";
  await signIn(page, "/secrets");
  await expect(page.getByRole("heading", { name: "Vault" })).toBeVisible();
  await page.getByText("Create a secret").click();
  await page.getByLabel("Name").fill("e2e-token");
  await page.getByLabel("Type").selectOption("token");
  await page.getByLabel(/^Value/).fill(value);
  await page.getByRole("button", { name: "Create secret" }).click();
  await expect(page.getByText("Created e2e-token as version 1.")).toBeVisible();
  await expect(page.getByLabel(/^Value/)).toHaveValue("");
  await page.getByRole("table", { name: "Secrets" }).getByRole("link", { name: "e2e-token" }).click();
  await expect(page.getByRole("table", { name: "References to e2e-token" }).or(page.getByText(/Nothing references this secret/))).toBeVisible();
  await page.getByRole("button", { name: "Rotate" }).click();
  await page.getByLabel("New value (write-only)").fill(rotated);
  await page.getByRole("dialog", { name: "Rotate e2e-token" }).getByRole("button", { name: "Rotate" }).click();
  await expect(page.getByText("Rotated to version 2.")).toBeVisible();
  const text = await page.locator("body").innerText();
  expect(text).not.toContain(value);
  expect(text).not.toContain(rotated);
  await page.getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("dialog", { name: "Revoke e2e-token" }).getByRole("button", { name: "Revoke e2e-token" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Secrets" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Secrets" }).or(page.getByText(/No secret is stored/))).not.toContainText("e2e-token");
});

test("G-13 approvals: a deep link to one approval opens after sign-in", async ({ page, browser }) => {
  claims("FR-8.21", "FR-8.28");
  await signIn(page, "/approvals");
  const call = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker, timeout: "60s" });
  try {
    const row = page.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: "ref_read_file" });
    await expect(row).toBeVisible({ timeout: 60_000 });
    const href = await row.getAttribute("href");
    expect(href).toMatch(/^\/approvals\/[0-9a-f-]+$/);
    const other = await browser.newPage({ ignoreHTTPSErrors: true });
    await signIn(other, href!, "approver");
    await expect(other.getByRole("heading", { level: 1, name: "Approval" })).toBeVisible();
    await other.getByRole("button", { name: "Deny this call" }).click();
    await expect(other.getByRole("definition").filter({ hasText: /^denied$/ })).toBeVisible();
    await other.close();
    const r = await call.done;
    expect(r.code).not.toBe(0);
  } finally {
    call.kill();
  }
});

test("G-14 audit investigation: event, call phases and the investigation graph", async ({ page }) => {
  claims("FR-8.22");
  await signIn(page, "/audit");
  await page.getByLabel("Class").fill("call");
  await page.getByRole("button", { name: "Apply filter" }).click();
  const table = page.getByRole("table", { name: "Journal events" });
  await expect(table).toContainText("call");
  await table.getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1, name: "Evidence event" })).toBeVisible();
  const id = page.url().split("/").pop()!;
  // Without Neo4j the mirror is disabled; the view says so.
  await expect(page.getByText("Not enabled on this Gateway.")).toBeVisible();
  // With the mirror, the path renders as a bounded graph: fixture.
  await mock(page, `**/api/v1/graph/events/${id}/path`, {
    event: { id, class: "call", phase: "delivered" },
    decision: { id: "d1", outcome: "permit", revisionId: "r1", decisiveRules: "ro-ref" },
    invocation: { id: "c1", phase: "delivered", outcome: "ok" },
    session: { id: "s1", state: "active" },
    principal: { id: "claude-code-local" },
    serverRevision: { id: "smcp-ref-filesystem@0.0.0" },
    toolRevision: { id: "live/echo", name: "echo" },
    policyRevision: { id: "r1" },
    phases: [{ id: "p1", phase: "requested" }, { id, phase: "delivered" }],
  });
  await page.reload();
  const graph = page.getByRole("group", { name: /Investigation path: 8 of 8/ });
  await expect(graph).toBeVisible();
  await expect(page.getByText("Decisive rules: ro-ref")).toBeVisible();
  await graph.getByRole("link", { name: /^PolicyRevision r1/ }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Policy revision r1" })).toBeVisible();
  // Neighborhood explorer, bounded by the limit: fixture.
  await mock(page, "**/api/v1/graph/neighborhood?**", {
    node: { id: "s1", labels: ["Session"], properties: {} },
    neighbors: [
      { id: "claude-code-local", labels: ["Principal"] },
      { id: "c1", labels: ["Invocation"] },
    ],
    edges: [
      { type: "OF_PRINCIPAL", from: "s1", to: "claude-code-local" },
      { type: "IN_SESSION", from: "c1", to: "s1" },
    ],
    degree: 41,
    truncated: true,
  });
  await go(page, "/audit/graph?label=Session&id=s1&limit=25");
  await expect(page.getByRole("group", { name: /2 of 41 relationships shown \(truncated/ })).toBeVisible();
  await expect(page.getByRole("table", { name: "Relationships" })).toContainText("OF_PRINCIPAL");
});

test("Egress: broker, grants and the connection log", async ({ page }) => {
  claims("FR-6.20");
  await signIn(page, "/egress");
  await expect(page.getByRole("heading", { name: "Broker" })).toBeVisible();
  await expect(page.getByText(/No server has an egress grant/)).toBeVisible();
  await page.getByLabel("Decision").selectOption("denied");
  await page.getByRole("button", { name: "Apply filter" }).click();
  await expect(page.getByText(/No egress operation matches/)).toBeVisible();
});

test("Runtime: launcher, prerequisites and instances", async ({ page }) => {
  claims("FR-5.20");
  await signIn(page, "/runtime");
  await expect(page.getByText("none: servers run as your user")).toBeVisible();
  await expect(page.getByRole("table", { name: "Prerequisite checks" })).toBeVisible();
  await expect(page.getByText(/No sandboxed instance exists/)).toBeVisible();
});

test("views show loading, empty and error states with the reason code and retry", async ({ page }) => {
  claims("FR-8.29");
  await signIn(page, "/");
  // Error state: the control API message and reason code, with Retry.
  await mock(page, "**/api/v1/egress/grants", { error: { code: "egress_broken", message: "grant table unreadable" } }, 500);
  await go(page, "/egress");
  const alert = page.getByRole("alert").filter({ hasText: "grant table unreadable" });
  await expect(alert).toContainText("egress_broken");
  await page.unroute("**/api/v1/egress/grants");
  await alert.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText(/No server has an egress grant/)).toBeVisible();
  // Loading state within 200 ms of navigation, shown while a slow route answers.
  await page.route("**/api/v1/runtime/instances", async (r) => {
    await new Promise((ok) => setTimeout(ok, 1500));
    await r.continue();
  });
  const t0 = Date.now();
  await go(page, "/runtime");
  await expect(page.getByText("Loading server instances")).toBeVisible();
  expect(Date.now() - t0).toBeLessThan(1000);
  await expect(page.getByText(/No sandboxed instance exists/)).toBeVisible();
});

test("each role sees only its views and actions", async ({ page }) => {
  claims("FR-8.2", "FR-8.28");
  const expectViews = async (names: string[], absent: string[]) => {
    for (const n of names) await expect(nav(page).getByRole("link", { name: n })).toBeVisible();
    for (const n of absent) await expect(nav(page).getByRole("link", { name: n })).toHaveCount(0);
  };
  await signIn(page, "/", "operator");
  await expectViews(["Gateway control", "Sessions and principals", "Runtime", "Data server and memory"], ["Research campaigns"]);
  await expect(page.getByTestId("emergency-button")).toBeVisible();
  await go(page, "/policy");
  await expect(page.getByRole("link", { name: "Draft", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "policy_author");
  await expectViews(["Policy studio", "Behavior analytics", "Research campaigns"], ["Secrets", "Runtime"]);
  await expect(page.getByTestId("emergency-button")).toHaveCount(0);
  await go(page, "/policy");
  await expect(page.getByRole("link", { name: "Draft", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "auditor");
  await expectViews(["Audit investigation", "Secrets", "Policy studio", "Research campaigns"], ["Approvals", "Remote access"]);
  await go(page, "/secrets");
  await expect(page.getByText("Create a secret")).toHaveCount(0);
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "researcher");
  await expectViews(["Research campaigns", "Observation workbench", "Behavior analytics"], ["Audit investigation", "Policy studio", "Secrets"]);
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "session_approver");
  await expect(page.getByRole("heading", { level: 1, name: "Remote access" })).toBeVisible();
  await expectViews(["Remote access", "Gateway control"], ["Sessions and principals", "Approvals", "Audit investigation"]);
  await expect(page.getByRole("button", { name: "Enable remote access" })).toHaveCount(0);
});

test("the OpenAPI document describes every route with its roles", async ({ request }) => {
  claims("FR-8.1");
  const login = await request.post(g.adminURL + "/admin/v1/login", { data: { username: "admin", password: g.adminPassword }, headers: { Origin: g.adminURL } });
  const { token } = (await login.json()) as { token: string };
  const res = await request.get(g.adminURL + "/api/v1/openapi.json", { headers: { Authorization: `Bearer ${token}` } });
  expect(res.status()).toBe(200);
  const doc = (await res.json()) as { openapi: string; paths: Record<string, Record<string, { "x-smcp-roles"?: string[] }>> };
  expect(doc.openapi).toBe("3.1.0");
  expect(doc.paths["/api/v1/policy/revisions"]?.post?.["x-smcp-roles"]).toEqual(["administrator", "policy_author"]);
  expect(doc.paths["/api/v1/filters/scan"]?.post).toBeTruthy();
});

// Last: suspending the reference server stops it until smcpd restarts.
test("G-10 servers and library: suspend, enable, trust anchors and receipts", async ({ page }) => {
  claims("FR-8.18", "FR-5.7");
  await signIn(page, "/servers");
  await expect(page.getByRole("table", { name: "Servers" })).toContainText("ref");
  await page.getByRole("link", { name: "Library and trust anchors" }).click();
  const revs = page.getByRole("table", { name: "Package revisions" });
  await expect(revs).toContainText("smcp-ref-filesystem");
  await expect(page.getByRole("table", { name: "Import receipts" })).toContainText("accepted");
  // Enroll and remove a trust anchor.
  const prefix = join(work, `anchor-${Date.now()}`);
  execFileSync(join(bin, "smcpctl"), ["package", "keygen", "--out", prefix, "--unencrypted"]);
  await page.getByText("Enroll a trust anchor").click();
  await page.getByLabel("Anchor name").fill("e2e-anchor");
  await page.getByLabel("Minisign public key (the .pub file)").fill(readFileSync(prefix + ".pub", "utf8"));
  await page.getByRole("button", { name: "Enroll anchor" }).click();
  await expect(page.getByRole("table", { name: "Trust anchors" })).toContainText("e2e-anchor");
  await page.getByRole("button", { name: "Remove e2e-anchor" }).click();
  await expect(page.getByRole("table", { name: "Trust anchors" })).not.toContainText("e2e-anchor");
  // Retire is offered; it is final, so it is not used here.
  await expect(revs.getByRole("button", { name: "Retire" })).toBeVisible();
  // Suspend the running server, then enable it again (needs a restart to run).
  await revs.getByRole("button", { name: "Suspend" }).click();
  await page.getByRole("dialog", { name: /Suspend smcp-ref-filesystem/ }).getByRole("button", { name: "Suspend" }).click();
  await expect(page.getByText(/Suspended smcp-ref-filesystem/)).toBeVisible();
  await expect(revs).toContainText("verified-disabled");
  await revs.getByRole("button", { name: "Enable" }).click();
  await page.getByRole("dialog", { name: /Enable smcp-ref-filesystem/ }).getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText(/Enabled smcp-ref-filesystem/)).toBeVisible();
  await expect(revs).toContainText("enabled");
  await page.getByRole("link", { name: "smcp-ref-filesystem" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Package smcp-ref-filesystem" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /^Signed manifest/ })).toBeVisible();
});
