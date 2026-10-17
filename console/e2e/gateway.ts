// Starts a real Gateway for the Playwright acceptance tests: builds smcpd,
// smcpctl, the reference server and the test MCP client, bootstraps a new
// instance in console/.e2e, adds an Approver account and an account for
// every other Appendix C role, enables the Secret Vault (passphrase key
// source) and the Egress Broker, turns desktop notifications off, moves
// the listeners to free ports and runs smcpd until teardown.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const consoleDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const repoRoot = resolve(consoleDir, "..");
export const work = join(consoleDir, ".e2e");
export const bin = join(work, "bin");
export const inst = join(work, "instance");
export const infoFile = join(work, "gateway.json");

export interface GatewayInfo {
  adminURL: string;
  publicURL: string;
  ca: string;
  config: string;
  adminPassword: string;
  approverUser: string;
  approverPassword: string;
  sessionApproverPassword: string;
  /** Console accounts by role (Operator, Policy Author, Auditor, Researcher); all use rolePassword. */
  roleUsers: Record<string, string>;
  rolePassword: string;
  marker: string;
  pid: number;
}

export function info(): GatewayInfo {
  return JSON.parse(readFileSync(infoFile, "utf8")) as GatewayInfo;
}

// Ports handed out by freePort in this run.
const issued = new Set<number>();

function bindable(port: number): Promise<boolean> {
  return new Promise((ok) => {
    const s = createServer();
    s.once("error", () => ok(false));
    s.listen(port, "127.0.0.1", () => s.close(() => ok(true)));
  });
}

// freePort returns a bindable loopback port below the ephemeral range
// (20000-32767) for a listener written into the configuration. A port from
// listen(0) is in the ephemeral range, where smcpd's own port-0 listeners
// (the egress proxy) can take it before the configured listener binds it,
// which made smcpd exit at startup with "address already in use".
async function freePort(): Promise<number> {
  for (let i = 0; i < 500; i++) {
    const p = 20000 + Math.floor(Math.random() * 12768);
    if (issued.has(p)) continue;
    issued.add(p);
    if (await bindable(p)) return p;
  }
  throw new Error("no free loopback port below the ephemeral range");
}

function secretFile(name: string, value: string): string {
  const p = join(work, name);
  writeFileSync(p, value, { mode: 0o600 });
  chmodSync(p, 0o600);
  return p;
}

let proc: ChildProcess | null = null;

export async function start(): Promise<GatewayInfo> {
  rmSync(work, { recursive: true, force: true });
  mkdirSync(bin, { recursive: true });
  if (process.env.SMCP_E2E_BIN) {
    for (const b of ["smcpd", "smcpctl", "smcp-refserver", "itest-client"]) execFileSync("cp", [join(process.env.SMCP_E2E_BIN, b), bin]);
  } else {
    execFileSync("go", ["build", "-o", bin + "/", "./cmd/smcpd", "./cmd/smcpctl", "./cmd/smcp-refserver", "./scripts/itest-client"], { cwd: repoRoot, stdio: "inherit" });
  }
  const adminPassword = "console-e2e-admin-pw";
  const sessionApproverPassword = "console-e2e-session-approver";
  const approverPassword = "console-e2e-approver-pw";
  const adminPw = secretFile("admin.pw", adminPassword);
  const saPw = secretFile("approver.pw", sessionApproverPassword);
  const apPw = secretFile("tool-approver.pw", approverPassword);
  const ctl = join(bin, "smcpctl");
  execFileSync(ctl, ["bootstrap", "--dir", inst, "--admin-password-file", adminPw, "--approver-password-file", saPw], { stdio: "inherit" });
  const config = join(inst, "smcp.toml");
  const harness = await freePort();
  const admin = await freePort();
  const metrics = await freePort();
  let toml = readFileSync(config, "utf8");
  toml = toml
    .replaceAll("127.0.0.1:8443", `127.0.0.1:${harness}`)
    .replaceAll("127.0.0.1:8444", `127.0.0.1:${admin}`)
    .replaceAll("127.0.0.1:8445", `127.0.0.1:${metrics}`);
  // Bootstrap may write an [approvals] table; desktop notifications stay off.
  const hasApprovals = /^\[approvals\]$/m.test(toml);
  toml = toml.replace(/^notify = ".*"$/m, 'notify = "off"');
  writeFileSync(config, toml);
  const remotePort = await freePort();
  const hash = execFileSync(ctl, ["hash-password", "--password-file", apPw], { encoding: "utf8" }).trim();
  const rolePassword = "console-e2e-role-password";
  const roleHash = execFileSync(ctl, ["hash-password", "--password-file", secretFile("role.pw", rolePassword)], { encoding: "utf8" }).trim();
  const roleUsers: Record<string, string> = { operator: "olga", policy_author: "pat", auditor: "aud", researcher: "rita" };
  const vaultPw = secretFile("vault.pw", "console-e2e-vault-passphrase");
  // Tables go before the arrays of tables so no key lands in the wrong table.
  appendFileSync(
    config,
    [
      ...(hasApprovals ? [] : ["", "[approvals]", 'notify = "off"']),
      "",
      "[egress]",
      "enabled = true",
      "",
      "[remote]",
      `address = "127.0.0.1:${remotePort}"`,
      "",
      "[secrets]",
      'key_source = "passphrase"',
      `passphrase_file = "${vaultPw}"`,
      "",
      "[[approvals.account]]",
      'username = "alice"',
      `password_hash = "${hash}"`,
      ...Object.entries(roleUsers).flatMap(([role, user]) => ["", "[[console.account]]", `username = "${user}"`, `password_hash = "${roleHash}"`, `role = "${role}"`]),
      "",
    ].join("\n"),
  );
  execFileSync(ctl, ["secrets", "init", "--config", config, "--passphrase-file", vaultPw], { stdio: "inherit" });
  const marker = `console-e2e-${Date.now()}`;
  writeFileSync(join(inst, "sandbox", "hello.txt"), marker + "\n");
  proc = spawn(join(bin, "smcpd"), ["--config", config], { stdio: ["ignore", "pipe", "pipe"], detached: false });
  const log: string[] = [];
  proc.stdout?.on("data", (d: Buffer) => log.push(d.toString()));
  proc.stderr?.on("data", (d: Buffer) => log.push(d.toString()));
  const g: GatewayInfo = {
    adminURL: `https://127.0.0.1:${admin}`,
    publicURL: `https://127.0.0.1:${harness}`,
    ca: join(inst, "state", "tls", "ca.crt"),
    config,
    adminPassword,
    approverUser: "alice",
    approverPassword,
    sessionApproverPassword,
    roleUsers,
    rolePassword,
    marker,
    pid: proc.pid ?? 0,
  };
  for (let i = 0; i < 120; i++) {
    if (proc.exitCode !== null) throw new Error("smcpd exited during startup:\n" + log.join(""));
    try {
      execFileSync(ctl, ["health", "--config", config], { stdio: "ignore" });
      writeFileSync(infoFile, JSON.stringify(g, null, 2));
      writeFileSync(join(work, "smcpd.pid"), String(proc.pid));
      proc.stdout?.removeAllListeners("data");
      proc.stderr?.removeAllListeners("data");
      proc.stdout?.resume();
      proc.stderr?.resume();
      return g;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error("smcpd did not become healthy within 60 s:\n" + log.join(""));
}

export function stop(): void {
  const pidFile = join(work, "smcpd.pid");
  if (proc && proc.exitCode === null) proc.kill("SIGTERM");
  else if (existsSync(pidFile)) {
    try {
      process.kill(Number(readFileSync(pidFile, "utf8")), "SIGTERM");
    } catch {
      // already gone
    }
  }
}

/** Runs the test MCP client: OAuth sign-in as the Session Approver, then one tool call. */
export function mcpCall(g: GatewayInfo, tool: string, args: object, opts: { scope?: string; expect?: string; timeout?: string; clientID?: string } = {}) {
  const a = ["-url", g.publicURL, "-ca", g.ca, "-call", tool, "-args", JSON.stringify(args), "-timeout", opts.timeout ?? "150s"];
  if (opts.scope) a.push("-scope", opts.scope);
  if (opts.clientID) a.push("-client-id", opts.clientID);
  if (opts.expect) a.push("-expect", opts.expect);
  const p = spawn(join(bin, "itest-client"), a, { env: { ...process.env, SMCP_SIGNIN_PASSWORD: g.sessionApproverPassword }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  p.stdout?.on("data", (d: Buffer) => (out += d.toString()));
  p.stderr?.on("data", (d: Buffer) => (out += d.toString()));
  const done = new Promise<{ code: number | null; out: string }>((ok) => p.on("exit", (code) => ok({ code, out })));
  return { done, kill: () => p.kill() };
}
