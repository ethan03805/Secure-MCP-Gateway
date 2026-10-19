// End-to-end test of the desktop application on Linux (SRS FR-20.8,
// FR-20.9, FR-20.5, FR-20.10, FR-20.15, FR-20.28): the real application in
// WebKitGTK under Xvfb, driven over W3C WebDriver by tauri-driver, runs
// first-run setup against the real smcpctl and smcpd, then client setup for
// Claude Code, then a deep link. It changes the user's home and systemd
// user units, so it runs only on a disposable CI runner (job desktop-e2e).
//
//   APP=<path of smcp-desktop, with smcpctl, smcpd and smcp-refserver
//   beside it> node e2e/webdriver.mjs     (tauri-driver on 127.0.0.1:4444)
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const APP = process.env.APP;
if (!APP || !process.env.SMCP_DESKTOP_E2E) {
  console.error("set APP and SMCP_DESKTOP_E2E=1; this test changes the home directory and systemd user units");
  process.exit(2);
}
const WD = process.env.WD_URL ?? "http://127.0.0.1:4444";
const HOME = os.homedir();
const ADMIN_PW = "e2e admin password 7f3a";
const APPROVER_PW = "e2e approver password 9c1d";
const AXE = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "node_modules", "axe-core", "axe.min.js"), "utf8");
const ELEMENT = "element-6066-11e4-a52e-4f735466cecc";

let failures = 0;
const fail = (/** @type {string} */ m) => {
  failures++;
  console.log(`FAIL ${m}`);
};
const ok = (/** @type {string} */ m) => console.log(`ok   ${m}`);
const sleep = (/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms));

/** @param {string} method @param {string} p @param {unknown} [body] */
async function wd(method, p, body) {
  const r = await fetch(WD + p, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  const j = /** @type {any} */ (await r.json().catch(() => ({})));
  if (!r.ok) throw new Error(`${method} ${p}: ${JSON.stringify(j.value ?? j).slice(0, 400)}`);
  return j.value;
}

/** Waits for fn to return a truthy value. @template T @param {() => Promise<T>} fn @param {string} what */
async function waitFor(fn, what, ms = 30000) {
  const end = Date.now() + ms;
  /** @type {unknown} */
  let last;
  while (Date.now() < end) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${what}${last ? `: ${last}` : ""}`);
}

const session = await waitFor(
  () => wd("POST", "/session", { capabilities: { alwaysMatch: { "tauri:options": { application: APP } } } }),
  "a WebDriver session",
  60000,
);
const S = `/session/${session.sessionId}`;

const script = (/** @type {string} */ s, /** @type {unknown[]} */ args = []) => wd("POST", `${S}/execute/sync`, { script: s, args });
/** The element reference of a W3C or legacy (JSON Wire) response. */
const ref = (/** @type {any} */ v) => {
  const id = v?.[ELEMENT] ?? v?.ELEMENT ?? (v && typeof v === "object" ? Object.values(v)[0] : undefined);
  if (typeof id !== "string") throw new Error(`no element reference in ${JSON.stringify(v)}`);
  return id;
};
const find = (/** @type {string} */ css) =>
  waitFor(async () => ref(await wd("POST", `${S}/element`, { using: "css selector", value: css })), `element ${css}`, 15000);
const findX = (/** @type {string} */ xp) =>
  waitFor(async () => ref(await wd("POST", `${S}/element`, { using: "xpath", value: xp })), `element ${xp}`, 15000);
const click = (/** @type {string} */ id) => wd("POST", `${S}/element/${id}/click`, {});
const type = (/** @type {string} */ id, /** @type {string} */ text) => wd("POST", `${S}/element/${id}/value`, { text });
const text = async (/** @type {string} */ css) => /** @type {string} */ (await wd("GET", `${S}/element/${await find(css)}/text`));
const button = (/** @type {string} */ label) => findX(`//button[normalize-space(.)=${JSON.stringify(label)}]`);

/** Switches to the window whose document title starts with prefix. */
async function windowTitled(/** @type {string} */ prefix, ms = 30000) {
  return waitFor(async () => {
    for (const h of /** @type {string[]} */ (await wd("GET", `${S}/window/handles`))) {
      await wd("POST", `${S}/window`, { handle: h });
      const t = /** @type {string} */ (await wd("GET", `${S}/title`));
      if (t.startsWith(prefix)) return h;
    }
    return null;
  }, `a window titled "${prefix}"`, ms);
}

/** axe-core with the WCAG 2.2 A and AA rules in the application's own webview (FR-20.15). */
async function axe(/** @type {string} */ name) {
  await script(`${AXE}; return true;`);
  const violations = await wd("POST", `${S}/execute/async`, {
    script: "const done = arguments[arguments.length - 1]; axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa'] } }).then(r => done(r.violations.map(v => v.id + ' ' + v.nodes.map(n => n.target.join(' ')).join(', '))), e => done(['axe error ' + e]));",
    args: [],
  });
  if (violations.length) fail(`axe ${name}: ${violations.join(" | ")}`);
  else ok(`axe ${name}: no WCAG 2.2 AA violation in WebKitGTK`);
}

const stageTitle = () => text("#stage-title").catch(() => "");

try {
  // ---- Introduction, then first-run setup (FR-20.40, FR-20.8) ----
  await windowTitled("Introduction");
  ok("the introduction opens at the first start");
  // Skip closes the window, so the click may report the window as gone.
  await click(await find("#skip")).catch((e) => {
    if (!String(e).includes("no such window")) throw e;
  });
  await windowTitled("Set Up the Gateway", 60000);
  await waitFor(() => find("#setup-form"), "the setup form", 60000);
  ok("first-run setup follows the introduction when no configuration exists");
  await axe("setup form");

  // FR-20.9: Enforced is offered only with every prerequisite; the
  // Standalone statement is shown before installation.
  const statement = await text("#standalone-statement");
  if (!/not enforced/.test(statement) || !/without container or network isolation/.test(statement)) fail(`standalone statement: ${statement}`);
  const enforced = await script("const e = document.getElementById('profile-enforced'); return e ? { disabled: e.disabled, missing: [...e.parentElement.querySelectorAll('li')].map(l => l.textContent) } : null;");
  if (!enforced) fail("Linux setup does not show the Enforced profile");
  else if (enforced.disabled && enforced.missing.length === 0) fail("Enforced is refused without naming a missing prerequisite");
  else ok(`Enforced ${enforced.disabled ? `refused, missing: ${enforced.missing.join("; ")}` : "offered: every prerequisite present"}`);

  await type(await find("#admin"), ADMIN_PW);
  await type(await find("#adminRepeat"), ADMIN_PW);
  await type(await find("#approver"), APPROVER_PW);
  await type(await find("#approverRepeat"), APPROVER_PW);

  // FR-20.8: no password in any process argument list, sampled every 100 ms.
  let samples = 0;
  let leaked = "";
  let sampling = true;
  const sampler = (async () => {
    while (sampling) {
      const ps = execFileSync("ps", ["-eo", "args"], { encoding: "utf8" });
      samples++;
      for (const l of ps.split("\n")) if (l.includes(ADMIN_PW) || l.includes(APPROVER_PW)) leaked = l;
      await sleep(100);
    }
  })();
  await click(await find('button[type="submit"]'));
  const done = await waitFor(async () => {
    const t = await stageTitle();
    return t && t !== "Setting up the Gateway" && t !== "Choose a profile and set two passwords" ? t : null;
  }, "setup to finish", 300000);
  sampling = false;
  await sampler;
  if (done !== "The Gateway is set up") {
    const out = await text("pre.output").catch(() => "");
    throw new Error(`setup ended with "${done}":\n${out}`);
  }
  ok("first-run setup completed through smcpctl install");
  if (leaked) fail(`a password appeared in a process argument list: ${leaked.slice(0, 120)}`);
  else ok(`no password in ${samples} argument-list samples`);
  const left = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith("smcp-setup-"));
  if (left.length) fail(`password files remain: ${left.join(", ")}`);
  else ok("no password file remains");
  const cfg = path.join(HOME, ".config", "smcp-gateway", "smcp.toml");
  if (!fs.existsSync(cfg)) fail(`no configuration at ${cfg}`);
  for (const pw of [ADMIN_PW, APPROVER_PW]) if (fs.readFileSync(cfg, "utf8").includes(pw)) fail("the configuration holds a password in clear");
  try {
    execFileSync("systemctl", ["--user", "is-active", "--quiet", "smcpd.service"]);
    ok("the smcpd user unit is active");
  } catch {
    fail("the smcpd user unit is not active");
  }
  // FR-20.5: metrics on the CP-51 address, with the desktop gauges.
  const metrics = await waitFor(async () => (await fetch("http://127.0.0.1:9464/metrics")).text(), "metrics on 127.0.0.1:9464");
  if (!/^smcp_release_enforced /m.test(metrics) || !/^smcp_emergency_stop /m.test(metrics)) fail("the metrics endpoint lacks the desktop gauges");
  else ok("metrics are on at 127.0.0.1:9464 with smcp_release_enforced and smcp_emergency_stop");
  await axe("setup done");

  // ---- Client setup (FR-20.10) ----
  const claudeJson = path.join(HOME, ".claude.json");
  const original = fs.readFileSync(claudeJson, "utf8");
  await click(await button("Set Up a Client"));
  await windowTitled("Set Up a Client", 30000);
  await waitFor(async () => (await stageTitle()) === "Agents on this computer", "the client list", 60000);
  await axe("client list");
  await click(await button("Connect Claude Code"));
  await waitFor(() => find("#lockdown"), "the preview", 60000);
  // The lockdown profile writes managed settings that need root; preview
  // and apply without it.
  await click(await find("#lockdown"));
  await waitFor(async () => !(await script("return [...document.querySelectorAll('h3')].some(h => h.textContent === 'Lockdown profile');")), "the preview without the lockdown", 60000);
  const changes = /** @type {string[]} */ (await script("return [...document.querySelectorAll('p.change')].map(p => p.textContent);"));
  if (!changes.some((c) => c.includes(claudeJson))) fail(`the preview does not name ${claudeJson}: ${changes.join(" | ")}`);
  else ok(`the preview names ${changes.length} change(s), including ${claudeJson}`);
  await axe("client preview");
  if (fs.readFileSync(claudeJson, "utf8") !== original) fail("a file changed before Connect");
  else ok("nothing was written before Connect");
  await click(await button("Connect"));
  await waitFor(async () => (await stageTitle()) === "Claude Code is connected", "Claude Code to connect", 60000);
  const after = fs.readFileSync(claudeJson, "utf8");
  if (!after.includes("127.0.0.1:8443") || !after.includes('"theme"')) fail(`~/.claude.json after connect: ${after.slice(0, 300)}`);
  else ok("Claude Code points at the Gateway and keeps its own settings");
  await click(await button("Back to the List"));
  await click(await waitFor(() => button("Disconnect Claude Code"), "Disconnect", 60000));
  await waitFor(async () => (await stageTitle()) === "Claude Code is disconnected", "Claude Code to disconnect", 60000);
  if (fs.readFileSync(claudeJson, "utf8") !== original) fail("~/.claude.json was not restored");
  else ok("Disconnect restored ~/.claude.json");

  // ---- Deep links (FR-20.28) ----
  const before = /** @type {string[]} */ (await wd("GET", `${S}/window/handles`)).length;
  spawn(APP, ["smcp://approvals"], { stdio: "ignore", detached: true }).unref();
  const consoleHref = await waitFor(async () => {
    const handles = /** @type {string[]} */ (await wd("GET", `${S}/window/handles`));
    if (handles.length <= before) return null;
    for (const h of handles) {
      await wd("POST", `${S}/window`, { handle: h });
      const href = /** @type {string} */ (await script("return location.href;"));
      // The console window starts at about:blank; the bundled windows are
      // tauri: pages, except the certificate error page.
      if (href.startsWith("https://") || href.includes("/error.html")) return href;
    }
    return null;
  }, "the console window", 60000).catch((e) => {
    fail(String(e));
    return "";
  });
  if (consoleHref) {
    if (!consoleHref.startsWith("https://127.0.0.1:8444/")) fail(`the console window shows ${consoleHref}`);
    else ok(`smcp://approvals opened the console window on the admin listener (${consoleHref})`);
    spawn(APP, ["smcp://approvals?approve=1"], { stdio: "ignore", detached: true }).unref();
    spawn(APP, ["smcp://stop"], { stdio: "ignore", detached: true }).unref();
    await sleep(3000);
    const now = /** @type {string} */ (await script("return location.href;"));
    if (now !== consoleHref) fail(`a refused link navigated the console window to ${now}`);
    else ok("refused links left the console window where it was");
  }
} catch (e) {
  fail(String(e instanceof Error ? e.stack : e));
} finally {
  await wd("DELETE", S).catch(() => undefined);
}
console.log(failures ? `${failures} failure(s)` : "desktop end-to-end: setup, client setup and deep links passed");
process.exit(failures ? 1 : 0);
