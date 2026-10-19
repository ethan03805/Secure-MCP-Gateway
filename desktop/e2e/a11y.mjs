// Accessibility and behavior check of the bundled windows in a browser
// engine (SRS FR-20.15, FR-20.43, FR-20.52): axe-core with the WCAG 2.2 A and
// AA rules on every introduction step and every tray state in the light and
// dark schemes, the windows under the application's CSP, keyboard use of
// the introduction, and reduced motion. Run after `npm run build`:
//   node e2e/a11y.mjs            (WebKit, the engine of WKWebView)
//   ENGINE=chromium node e2e/a11y.mjs
//   SHOTS=<dir> node e2e/a11y.mjs  also saves a screenshot of each page
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, webkit } from "playwright";
import { AxeBuilder } from "@axe-core/playwright";

const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist");
const conf = JSON.parse(fs.readFileSync(path.join(dist, "..", "src-tauri", "tauri.conf.json"), "utf8"));
// The application's CSP, minus the IPC sources a browser does not have.
const csp = conf.app.security.csp;
const shots = process.env.SHOTS ? path.resolve(process.env.SHOTS) : "";
if (shots) fs.mkdirSync(shots, { recursive: true });

const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };
const server = http.createServer((req, res) => {
  const u = new URL(req.url ?? "/", "http://x");
  const p = path.join(dist, decodeURIComponent(u.pathname));
  if (!p.startsWith(dist) || !fs.existsSync(p) || fs.statSync(p).isDirectory()) {
    res.writeHead(404);
    res.end();
    return;
  }
  const h = { "content-type": types[path.extname(p)] ?? "application/octet-stream" };
  // axe injects its own script and styles, so only the pages loaded with
  // ?csp (and their subresources) get the application's policy.
  if (u.searchParams.has("csp") || (req.headers.referer ?? "").includes("csp")) h["content-security-policy"] = csp;
  res.writeHead(200, h);
  fs.createReadStream(p).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", () => r(undefined)));
const base = `http://127.0.0.1:${/** @type {import("node:net").AddressInfo} */ (server.address()).port}`;

let failures = 0;
const fail = (/** @type {string} */ m) => {
  failures++;
  console.log(`FAIL ${m}`);
};

/** @param {import("playwright").Page} page @param {string} name */
async function axe(page, name) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  for (const v of r.violations) fail(`axe ${name}: ${v.id} (${v.nodes.map((n) => n.target.join(" ")).join(", ")})`);
}

/** @param {import("playwright").Page} page */
function errorsOf(page) {
  /** @type {string[]} */
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });
  return errors;
}

const STEPS = 4;
const STATES = [
  ["healthy", 1],
  ["degraded", 1],
  ["degraded", 0],
  ["fail-closed", 0],
  ["emergency-stop", 0],
  ["stopped", 0],
  ["unreachable", 0],
];

const SETUP_DEMOS = ["form", "form-enforced", "form-missing", "running", "failed", "done", "configured", "missing-smcpctl"];

const engine = process.env.ENGINE === "chromium" ? chromium : webkit;
const browser = await engine.launch();
for (const scheme of /** @type {const} */ (["light", "dark"])) {
  const ctx = await browser.newContext({ viewport: { width: 600, height: 560 }, colorScheme: scheme, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  const errors = errorsOf(page);
  for (let i = 1; i <= STEPS; i++) {
    await page.goto(`${base}/intro.html?step=${i}&unavailable=setup,client-setup`);
    await page.waitForSelector("#step-body p");
    if (shots) await page.screenshot({ path: `${shots}/intro-step${i}-${scheme}.png`, fullPage: true });
    await axe(page, `introduction step ${i} (${scheme})`);
  }
  for (const [state, enforced] of STATES) {
    const name = `status-${state}${state === "degraded" && !enforced ? "-not-enforced" : ""}`;
    await page.goto(`${base}/status.html?state=${state}&enforced=${enforced}&pending=${state === "healthy" ? 2 : 0}&last=14:02:11`);
    await page.waitForSelector("#meaning:not(:empty)");
    if (shots) await page.screenshot({ path: `${shots}/${name}-${scheme}.png`, fullPage: true });
    await axe(page, `${name} (${scheme})`);
  }
  for (const p of ["settings.html", "error.html"]) {
    await page.goto(`${base}/${p}`);
    await axe(page, `${p} (${scheme})`);
  }
  // First-run setup in each of its stages (FR-20.8, FR-20.9, FR-20.15).
  for (const d of SETUP_DEMOS) {
    await page.goto(`${base}/setup.html?demo=${d}`);
    await page.waitForSelector("#stage-title");
    if (shots) await page.screenshot({ path: `${shots}/setup-${d}-${scheme}.png`, fullPage: true });
    await axe(page, `setup ${d} (${scheme})`);
  }
  // settings.html rejects outside the application; only the introduction
  // and status pages must run without an error here.
  const own = errors.filter((e) => !e.includes("only inside the desktop application"));
  if (own.length) fail(`page errors (${scheme}): ${own.join(" | ")}`);
  await ctx.close();
}

// Under the application's CSP the pages load and run with no error (SR-2-6).
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = errorsOf(page);
  await page.goto(`${base}/intro.html?csp`);
  await page.waitForSelector("#step-body p");
  await page.goto(`${base}/status.html?csp&state=stopped`);
  await page.waitForSelector("#meaning:not(:empty)");
  await page.goto(`${base}/setup.html?csp&demo=failed`);
  await page.waitForSelector("#stage-title");
  if (errors.length) fail(`errors under the CSP: ${errors.join(" | ")}`);
  await ctx.close();
}

// Reduced motion: no animation on a change of step (FR-20.43, FR-20.52).
{
  const ctx = await browser.newContext({ reducedMotion: "reduce" });
  const page = await ctx.newPage();
  await page.goto(`${base}/intro.html`);
  await page.click("#next");
  const anim = await page.evaluate(() => getComputedStyle(/** @type {Element} */ (document.getElementById("step"))).animationName);
  if (anim !== "none") fail(`reduced motion: the step still animates (${anim})`);
  await ctx.close();
}
await browser.close();

// Keyboard (FR-20.43). Chromium: WebKit on macOS moves Tab focus to text
// fields only, as Safari does by default.
const kb = await chromium.launch();
{
  const ctx = await kb.newContext();
  const page = await ctx.newPage();
  /** @type {string[]} */
  const calls = [];
  await page.exposeFunction("recordCall", (/** @type {string} */ c) => calls.push(c));
  await page.addInitScript(() =>
    document.addEventListener("smcp-call", (e) => {
      const d = /** @type {CustomEvent} */ (e).detail;
      /** @type {any} */ (window).recordCall(d.cmd + (d.args ? " " + JSON.stringify(d.args) : ""));
    }),
  );
  await page.goto(`${base}/intro.html`);
  await page.waitForSelector("#step-body p");
  const focused = () => page.evaluate(() => document.activeElement?.id ?? "");
  if ((await focused()) !== "step-title") fail(`initial focus on ${await focused()}, not the heading`);
  for (let i = 2; i <= STEPS; i++) {
    // Tab to Next: Skip, then (from step 2) Back, then Next; step actions come first.
    await page.locator("#next").focus();
    await page.keyboard.press("Enter");
    const ann = (await page.textContent("#announce")) ?? "";
    if ((await focused()) !== "step-title") fail(`step ${i}: focus on ${await focused()}, not the heading`);
    if (!ann.startsWith(`Step ${i} of ${STEPS}: `)) fail(`step ${i}: announced "${ann}"`);
  }
  await page.keyboard.press("Tab");
  const tag = await page.evaluate(() => document.activeElement?.tagName ?? "");
  if (tag !== "BUTTON") fail(`Tab from the heading reaches ${tag}, not a control`);
  await page.keyboard.press("Escape");
  if (calls.at(-1) !== 'intro_close {"flag":"skipped"}') fail(`Escape did not skip: ${calls.join(", ")}`);
  await page.goto(`${base}/intro.html`);
  await page.waitForSelector("#step-body p");
  for (let i = 1; i <= STEPS; i++) {
    await page.locator("#next").focus();
    await page.keyboard.press("Enter");
  }
  if (calls.at(-1) !== 'intro_close {"flag":"completed"}') fail(`Done did not complete: ${calls.join(", ")}`);

  // First-run setup by keyboard alone (FR-20.15): focus starts on the
  // heading, Tab reaches the profile and the four password fields in
  // order, a mismatch is reported on its field, and Enter submits.
  await page.goto(`${base}/setup.html?demo=form-enforced`);
  await page.waitForSelector("#stage-title");
  if ((await focused()) !== "stage-title") fail(`setup: initial focus on ${await focused()}, not the heading`);
  await page.keyboard.press("Tab");
  if ((await focused()) !== "profile-standalone") fail(`setup: Tab reaches ${await focused()}, not the profile`);
  await page.keyboard.press("ArrowDown");
  if ((await focused()) !== "profile-enforced") fail(`setup: arrow key reaches ${await focused()}, not Enforced`);
  const typeInto = async (/** @type {string} */ id, /** @type {string} */ text) => {
    await page.keyboard.press("Tab");
    if ((await focused()) !== id) fail(`setup: Tab reaches ${await focused()}, not ${id}`);
    await page.keyboard.type(text);
  };
  await typeInto("admin", "admin password 1");
  await typeInto("adminRepeat", "admin password 1");
  await typeInto("approver", "approver password 2");
  await typeInto("approverRepeat", "approver password X");
  await page.keyboard.press("Enter");
  if ((await focused()) !== "approverRepeat") fail(`setup: a mismatch moves focus to ${await focused()}`);
  const err = (await page.textContent("#approverRepeat-error")) ?? "";
  if (!err.includes("Approver password are different")) fail(`setup: mismatch message "${err}"`);
  if (calls.some((c) => c.startsWith("setup_run"))) fail("setup: setup_run was called with mismatched passwords");
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.type("approver password 2");
  await page.keyboard.press("Enter");
  const run = calls.find((c) => c.startsWith("setup_run")) ?? "";
  if (run !== 'setup_run {"profile":"enforced","admin":"admin password 1","approver":"approver password 2"}') fail(`setup: submitted ${run || "nothing"}`);
  // A failed setup: Try Again by keyboard returns to the form.
  await page.goto(`${base}/setup.html?demo=failed`);
  await page.waitForSelector("#stage-title");
  if ((await focused()) !== "stage-title") fail(`setup failed: focus on ${await focused()}`);
  await page.getByRole("button", { name: "Try Again" }).focus();
  await page.keyboard.press("Enter");
  if ((await focused()) !== "stage-title" || !(await page.$("#setup-form"))) fail("setup: Try Again did not return to the form");
  await ctx.close();
}
await kb.close();
server.close();
console.log(failures ? `${failures} failure(s)` : "bundled windows: accessibility, CSP, motion and keyboard checks passed");
process.exit(failures ? 1 : 0);
