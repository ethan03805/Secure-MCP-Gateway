// Client setup (SRS FR-20.10, FR-20.46, FR-20.47). Pure functions:
// clients-view.ts renders them; the Rust side (clients.rs) runs
// `smcpctl clients detect` and `smcpctl connect`. Wording follows
// docs/design/writing.md; tools/uilint checks it.

export interface Client {
  id: string;
  name: string;
  installed: boolean;
  connected: boolean;
  lockdown: boolean;
  lockdownAvailable: boolean;
}

export interface Outcome {
  ok: boolean;
  code?: string | null;
  command: string;
  detail: string;
  output: string;
}

export interface ClientsView {
  gatewaySetUp: boolean;
  smcpctl: boolean;
  clients: Client[];
  failure?: Outcome | null;
}

export interface Change {
  path: string;
  scope: string;
  purpose: string;
  action: string;
  content: string;
}

export interface Plan {
  changes: Change[];
  commands: string[][];
  notes: string[];
}

export interface Preview {
  client: string;
  name: string;
  setup: Plan;
  lockdown?: Plan | null;
}

/** Help text of the lockdown choice (FR-20.46): what it does and when to choose it. */
export const LOCKDOWN_HELP =
  "The lockdown profile uses the agent's own managed settings to allow only the Gateway as an MCP server and to keep the agent from editing those settings. Choose it unless you need the agent to use MCP servers outside the Gateway.";

/** Help text of the remove control (FR-20.46). */
export const REMOVE_HELP = "Disconnect restores the agent's settings files to how they were before setup, including the lockdown profile.";

/** How the window describes a change's scope. */
export const SCOPE_TEXT: Record<string, string> = {
  user: "your user settings",
  project: "this project's settings",
  managed: "managed settings for this computer",
};

/** The empty state to show, by catalogue code, or null when the list has entries. */
export function emptyState(v: ClientsView): string | null {
  if (!v.smcpctl) return "SETUP_SMCPCTL_MISSING";
  if (!v.gatewaySetUp) return "CLIENTS_GATEWAY_NOT_SET_UP";
  if (v.failure) return v.failure.code ?? "CLIENTS_DETECT_FAILED";
  if (!v.clients.some((c) => c.installed)) return "CLIENTS_NONE_DETECTED";
  return null;
}

/** Whether to show the "no agent connected yet" state above the list. */
export function noneConnected(v: ClientsView): boolean {
  return emptyState(v) === null && !v.clients.some((c) => c.connected);
}

/** Installed clients first, then the supported ones not found here. */
export function partition(clients: readonly Client[]): { found: Client[]; others: Client[] } {
  return { found: clients.filter((c) => c.installed), others: clients.filter((c) => !c.installed) };
}

export function statusText(c: Client): string {
  if (c.connected) return c.lockdown ? "Connected, with the lockdown profile" : "Connected";
  return "Not connected";
}

export function changeLine(c: Change): string {
  const verb = c.action === "update" ? "Change" : "Create";
  return `${verb} ${c.path} (${SCOPE_TEXT[c.scope] ?? c.scope}): ${c.purpose}`;
}

/** The number of files a preview changes, for the confirmation text. */
export function fileCount(p: Preview): number {
  return new Set([...p.setup.changes, ...(p.lockdown?.changes ?? [])].map((c) => c.path)).size;
}

/** The details area of a failure (FR-20.47). */
export function details(o: Outcome): string {
  const lines = [`Code: ${o.code ?? ""}`, o.detail];
  if (o.command) lines.push("", "Command:", `  ${o.command}`);
  if (o.output) lines.push("", "Output of smcpctl:", o.output.trimEnd());
  return lines.join("\n");
}
