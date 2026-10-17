// Starts a real Gateway for the Playwright acceptance tests: builds smcpd,
// smcpctl, the reference server and the test MCP client, bootstraps a new
// instance in console/.e2e, adds an Approver account, moves the listeners
// to free ports and runs smcpd until teardown.
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
  marker: string;
  pid: number;
}

export function info(): GatewayInfo {
  return JSON.parse(readFileSync(infoFile, "utf8")) as GatewayInfo;
}

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      s.close(() => (typeof a === "object" && a ? ok(a.port) : fail(new Error("no port"))));
    });
  });
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
  let toml = readFileSync(config, "utf8");
  toml = toml.replaceAll("127.0.0.1:8443", `127.0.0.1:${harness}`).replaceAll("127.0.0.1:8444", `127.0.0.1:${admin}`);
  writeFileSync(config, toml);
  const hash = execFileSync(ctl, ["hash-password", "--password-file", apPw], { encoding: "utf8" }).trim();
  appendFileSync(config, `\n[[approvals.account]]\nusername = "alice"\npassword_hash = "${hash}"\n`);
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
export function mcpCall(g: GatewayInfo, tool: string, args: object, opts: { scope?: string; expect?: string; timeout?: string } = {}) {
  const a = ["-url", g.publicURL, "-ca", g.ca, "-call", tool, "-args", JSON.stringify(args), "-timeout", opts.timeout ?? "150s"];
  if (opts.scope) a.push("-scope", opts.scope);
  if (opts.expect) a.push("-expect", opts.expect);
  const p = spawn(join(bin, "itest-client"), a, { env: { ...process.env, SMCP_SIGNIN_PASSWORD: g.sessionApproverPassword }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  p.stdout?.on("data", (d: Buffer) => (out += d.toString()));
  p.stderr?.on("data", (d: Buffer) => (out += d.toString()));
  const done = new Promise<{ code: number | null; out: string }>((ok) => p.on("exit", (code) => ok({ code, out })));
  return { done, kill: () => p.kill() };
}
