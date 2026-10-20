// End-to-end test of the desktop application on macOS (SRS FR-20.6,
// SR-2.8-5, FR-20.28): Apple offers no WebDriver for WKWebView, so
// tauri-driver cannot drive the windows here (it drives WebKitGTK on Linux,
// webdriver.mjs). This test runs the parts that need no automation: a
// Gateway bootstrapped in a temporary home and run in the foreground
// (smcpctl bootstrap, smcpd on free loopback ports; no launchd agent), the
// application started with HOME set to that home and its settings pointing
// at the Gateway's admin listener and CA, a link at start that opens the
// console window (whose first page loads through WebKit after the
// certificate hook is installed), and links handed to the running copy.
//
//   APP=<smcp-desktop> BIN=<dir with smcpd, smcpctl, smcp-refserver>
//   SMCP_DESKTOP_E2E=1 node e2e/macos.mjs
//
// It starts windows on the desktop of the user who runs it; CI runs it on
// the macos-15 runner of the desktop job.
import { execFileSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { consoleAndLinks } from "./console.mjs";
import { Results } from "./results.mjs";

const APP = process.env.APP;
const BIN = process.env.BIN;
if (!APP || !BIN || !process.env.SMCP_DESKTOP_E2E) {
  console.error("set APP, BIN and SMCP_DESKTOP_E2E=1; this test starts the application's windows");
  process.exit(2);
}

/** A free loopback port. @returns {Promise<number>} */
const freePort = () =>
  new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      const port = typeof a === "object" && a ? a.port : 0;
      s.close(() => resolve(port));
    });
  });

const r = new Results("e2e::macos", {
  console_window: ["FR-20.6", "SR-2.8-5"],
  deep_links: ["FR-20.28"],
});

const home = fs.mkdtempSync(path.join(os.tmpdir(), "smcp-desktop-e2e-"));
const gw = path.join(home, "gateway");
fs.mkdirSync(gw, { mode: 0o700 });
const pw = (/** @type {string} */ name) => {
  const p = path.join(home, name);
  fs.writeFileSync(p, crypto.randomBytes(18).toString("hex"), { mode: 0o600 });
  return p;
};
const [port, adminPort, metricsPort] = [await freePort(), await freePort(), await freePort()];
const admin = `https://127.0.0.1:${adminPort}`;
/** @type {import("node:child_process").ChildProcess | null} */
let smcpd = null;
try {
  execFileSync(
    path.join(BIN, "smcpctl"),
    ["bootstrap", "--dir", gw, "--port", String(port), "--admin-port", String(adminPort), "--metrics-port", String(metricsPort), "--notify", "off",
      "--admin-password-file", pw("admin.pw"), "--approver-password-file", pw("approver.pw"), "--refserver", path.join(BIN, "smcp-refserver")],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  const cfg = path.join(gw, "smcp.toml");
  smcpd = spawn(path.join(BIN, "smcpd"), ["--config", cfg], { stdio: ["ignore", fs.openSync(path.join(home, "smcpd.log"), "a"), fs.openSync(path.join(home, "smcpd.log"), "a")] });
  const end = Date.now() + 60000;
  for (;;) {
    try {
      execFileSync(path.join(BIN, "smcpctl"), ["health", "--config", cfg], { stdio: "ignore" });
      break;
    } catch {
      if (Date.now() > end) throw new Error(`smcpd did not answer within 60 s:\n${fs.readFileSync(path.join(home, "smcpd.log"), "utf8").slice(-2000)}`);
      await new Promise((res) => setTimeout(res, 500));
    }
  }
  console.log(`ok   smcpd runs: admin listener ${admin}, metrics 127.0.0.1:${metricsPort}`);

  // The application's settings in the temporary home (Tauri's
  // configuration directory follows HOME). The introduction opens at this
  // first start and stays open beside the console window.
  const appDir = path.join(home, "Library", "Application Support", "com.smcp.desktop");
  fs.mkdirSync(appDir, { recursive: true });
  fs.writeFileSync(
    path.join(appDir, "settings.json"),
    JSON.stringify({
      admin_url: admin,
      metrics_address: `127.0.0.1:${metricsPort}`,
      ca_file: path.join(gw, "state", "tls", "ca.crt"),
      notifications: false,
      start_at_login: false,
      update_checks: false,
    }),
  );
  await consoleAndLinks(APP, admin, r, { secondStarts: true, env: { ...process.env, HOME: home } });
} catch (e) {
  r.begin("console_window");
  r.fail(String(e instanceof Error ? e.stack : e));
} finally {
  smcpd?.kill();
}
const passed = r.write();
fs.rmSync(home, { recursive: true, force: true });
console.log(passed ? "desktop end-to-end (macOS): console window and deep links passed" : `${r.failures} failure(s)`);
process.exit(passed ? 0 : 1);
