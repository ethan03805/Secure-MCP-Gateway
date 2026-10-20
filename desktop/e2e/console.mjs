// The console window (FR-20.6, SR-2.8-5) and deep links (FR-20.28) with
// the application running on its own, without WebDriver: a link is passed
// as an argument, as the Linux desktop entry does; the application logs
// each console page it opens ("smcp-desktop: console: <url>"), each
// refusal of the listener's certificate and each tray state. Used by
// webdriver.mjs (Linux, after setup) and macos.mjs.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const sleep = (/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms));

/** Waits for fn to return a truthy value. @template T @param {() => Promise<T>} fn @param {string} what */
async function waitFor(fn, what, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const v = await fn();
      if (v) return v;
    } catch {
      // retried
    }
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${what}`);
}

/**
 * @param {string} app the smcp-desktop executable
 * @param {string} admin the admin listener's origin, e.g. https://127.0.0.1:8444
 * @param {import("./results.mjs").Results} r results; uses the tests "console_window" and "deep_links"
 * @param {{ secondStarts?: boolean, env?: NodeJS.ProcessEnv }} [opts] secondStarts: also hand links to the running copy
 */
export async function consoleAndLinks(app, admin, r, opts = {}) {
  const LOG = path.join(os.tmpdir(), `smcp-desktop-direct-${process.pid}.log`);
  fs.writeFileSync(LOG, "");
  const startApp = (/** @type {string[]} */ args) => {
    const fd = fs.openSync(LOG, "a");
    return spawn(app, args, { stdio: ["ignore", fd, fd], env: opts.env ?? process.env });
  };
  const consoleLines = () => fs.readFileSync(LOG, "utf8").split("\n").filter((l) => l.startsWith("smcp-desktop: console: "));
  /** Waits at most 30 s for a second start to hand its link over and exit. */
  const exitOf = (/** @type {import("node:child_process").ChildProcess} */ p) =>
    new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        p.kill();
        reject(new Error("a second start did not exit within 30 s"));
      }, 30000);
      p.on("exit", () => {
        clearTimeout(t);
        resolve(undefined);
      });
    });
  const first = startApp(["smcp://approvals"]);
  let exited = /** @type {number | null | string} */ (null);
  first.on("exit", (code, sig) => (exited = code ?? sig));
  try {
    r.begin("console_window");
    await waitFor(async () => consoleLines().some((l) => l.endsWith(` ${admin}/approvals`)), "smcp://approvals to open the console at Approvals", 60000);
    r.ok(`smcp://approvals at start opened the console window at ${admin}/approvals`);
    // The tray state is set with the console window open. (The second
    // starts below show that the main loop still processes events: the
    // first page is loaded through WebKit, not a Tauri navigation.)
    await waitFor(async () => /smcp-desktop: tray: /.test(fs.readFileSync(LOG, "utf8")), "the tray state with the console window open", 20000);
    r.ok("the tray state is set with the console window open");
    await sleep(5000);
    const log = fs.readFileSync(LOG, "utf8");
    if (exited !== null) r.fail(`the application exited (${exited}) after opening the console window`);
    else if (/console refused/.test(log)) r.fail(`the console window refused the Gateway's certificate: ${log.split("\n").filter((l) => l.includes("refused")).join(" | ")}`);
    else r.ok("the console window accepted the admin listener's certificate (CA-pinned) and the application keeps running");

    r.begin("deep_links");
    if (!opts.secondStarts) {
      r.ok("the link at start was parsed and opened its page (second starts not checked on this platform)");
      return;
    }
    const n = consoleLines().length;
    for (const bad of ["smcp://approvals?approve=1", "smcp://stop", "smcp://approvals/not-a-uuid", `smcp://approvals/${"a".repeat(64 * 1024)}`]) {
      const p = startApp([bad]);
      await exitOf(p);
    }
    await sleep(2000);
    const ignored = fs.readFileSync(LOG, "utf8").split("\n").filter((l) => l === "smcp-desktop: second start: link ignored").length;
    if (consoleLines().length !== n) r.fail(`a refused link opened a console page: ${consoleLines().slice(n).join(" | ")}`);
    else if (ignored !== 4) r.fail(`the running application ignored ${ignored} of the 4 refused links it should have received`);
    else r.ok("the 4 refused links reached the running application, which ignored them");
    const id = "0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2b";
    const p = startApp([`smcp://approvals/${id}`]);
    await exitOf(p);
    await waitFor(async () => consoleLines().slice(n).some((l) => l.endsWith(`/approvals/${id}`)), "an approval link to reach the running application", 20000);
    r.ok("an approval link reached the running application, which opened that approval in the console window");
  } catch (e) {
    r.fail(String(e instanceof Error ? e.stack : e));
    console.log(`application output:\n${fs.readFileSync(LOG, "utf8").split("\n").filter((l) => !l.includes("xdg-desktop-portal")).slice(-40).join("\n")}`);
  } finally {
    first.kill();
  }
}
