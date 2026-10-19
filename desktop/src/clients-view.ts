// The Set Up a Client window (SRS FR-20.10, FR-20.15, FR-20.46, FR-20.47).
// It calls only the commands its capability grants
// (capabilities/clients.json). Nothing is written before the user selects
// Connect on the preview of exactly that choice.
import { catalogue } from "./catalogue.js";
import { byId, el, invoke } from "./dom.ts";
import { message, type MessageCatalogue } from "./setup-model.ts";
import {
  changeLine,
  details,
  emptyState,
  fileCount,
  LOCKDOWN_HELP,
  noneConnected,
  partition,
  REMOVE_HELP,
  statusText,
  type Client,
  type ClientsView,
  type Outcome,
  type Plan,
  type Preview,
} from "./clients-model.ts";

const cat = catalogue as unknown as MessageCatalogue;
const q = new URLSearchParams(location.search);
const demoMode = q.has("demo");

function show(nodes: Node[], busy = false): void {
  const s = byId("stage");
  s.replaceChildren(...nodes);
  s.setAttribute("aria-busy", String(busy));
}

function heading(text: string): HTMLElement {
  return el("h2", { id: "stage-title", tabindex: "-1" }, [text]);
}

function enter(title: string): void {
  document.title = `Set Up a Client: ${title}`;
  byId("stage-title").focus();
  byId("announce").textContent = title;
}

function button(label: string, onClick: () => void, primary = false, describedBy?: string): HTMLElement {
  const attrs: Record<string, string> = { type: "button" };
  if (primary) attrs.class = "primary";
  if (describedBy) attrs["aria-describedby"] = describedBy;
  const b = el("button", attrs, [label]);
  b.addEventListener("click", onClick);
  return b;
}

function messageNodes(code: string, vars: Record<string, string> = {}): HTMLElement[] {
  const m = message(cat, code, vars);
  const nodes = [heading(m.title), el("p", {}, [m.what])];
  if (m.why) nodes.push(el("p", {}, [m.why]));
  nodes.push(el("p", {}, [m.todo]));
  return nodes;
}

function detailsArea(o: Outcome): HTMLElement {
  const text = details(o);
  const status = el("span", { role: "status", class: "help" }, []);
  const copy = button("Copy Details", () => {
    navigator.clipboard?.writeText(text).then(
      () => (status.textContent = "Copied."),
      () => (status.textContent = "Select the text above and copy it."),
    );
  });
  return el("details", { open: "" }, [
    el("summary", {}, ["Details"]),
    el("pre", { class: "output", tabindex: "0", "aria-label": "Code, command and output of smcpctl" }, [text]),
    el("div", { class: "actions-inline" }, [copy, status]),
  ]);
}

function lookAgain(): HTMLElement {
  return button("Look Again", () => void load(), true);
}

// ---- List ----

function clientRow(c: Client): HTMLElement {
  const actions: HTMLElement[] = [];
  if (c.connected) {
    actions.push(button(`Disconnect ${c.name}`, () => void remove(c), false, "remove-help"));
  } else {
    actions.push(button(`Connect ${c.name}`, () => void preview(c, c.lockdownAvailable), true));
  }
  return el("li", {}, [el("div", {}, [el("strong", {}, [c.name]), el("span", { class: "help" }, [statusText(c)])]), el("div", { class: "actions-inline" }, actions)]);
}

function renderList(v: ClientsView): void {
  const empty = emptyState(v);
  if (empty) {
    const nodes = messageNodes(empty, { client: "" });
    if (v.failure) nodes.push(detailsArea(v.failure));
    if (empty === "CLIENTS_NONE_DETECTED") {
      const { others } = partition(v.clients);
      nodes.push(el("h3", {}, ["Supported agents"]), el("ul", {}, others.map((c) => el("li", {}, [c.name]))));
    }
    if (empty !== "CLIENTS_GATEWAY_NOT_SET_UP" && empty !== "SETUP_SMCPCTL_MISSING") nodes.push(el("div", { class: "actions-inline" }, [lookAgain()]));
    show(nodes);
    enter(message(cat, empty, { client: "" }).title);
    return;
  }
  const { found, others } = partition(v.clients);
  const title = heading("Agents on this computer");
  const nodes: Node[] = [title, el("p", {}, ["Connect an agent to send its tool calls through the Gateway. Before anything changes, the next page shows each change to the agent's settings."])];
  if (noneConnected(v)) {
    const m = message(cat, "CLIENTS_NONE_CONNECTED");
    nodes.push(el("p", { class: "note" }, [`${m.what} ${m.todo}`]));
  }
  nodes.push(el("ul", { class: "client-list" }, found.map(clientRow)));
  nodes.push(el("p", { id: "remove-help", class: "help" }, [REMOVE_HELP]));
  if (others.length) nodes.push(el("h3", {}, ["Supported agents not found here"]), el("p", { class: "help" }, [others.map((c) => c.name).join(", ")]));
  nodes.push(el("div", { class: "actions-inline" }, [button("Look Again", () => void load())]));
  show(nodes);
  enter("Agents on this computer");
}

// ---- Preview ----

function planNodes(label: string, p: Plan): Node[] {
  const nodes: Node[] = [el("h3", {}, [label])];
  if (!p.changes.length) nodes.push(el("p", { class: "help" }, ["No file changes."]));
  for (const c of p.changes) {
    nodes.push(el("p", { class: "change" }, [changeLine(c)]));
    nodes.push(el("pre", { class: "output", tabindex: "0", "aria-label": `New content of ${c.path}` }, [c.content]));
  }
  for (const cmd of p.commands) nodes.push(el("p", {}, ["Also runs: ", el("code", {}, [cmd.join(" ")])]));
  for (const n of p.notes) nodes.push(el("p", { class: "note" }, [n]));
  return nodes;
}

function renderPreview(c: Client, p: Preview, lockdown: boolean): void {
  const title = heading(`Connect ${c.name}`);
  const nodes: Node[] = [title, el("p", {}, [`Selecting Connect makes these changes to ${fileCount(p)} file${fileCount(p) === 1 ? "" : "s"}. Nothing has been changed yet.`])];
  if (c.lockdownAvailable) {
    const box = el("input", { type: "checkbox", id: "lockdown", "aria-describedby": "lockdown-help" });
    if (box instanceof HTMLInputElement) box.checked = lockdown;
    box.addEventListener("change", () => void preview(c, (box as HTMLInputElement).checked));
    nodes.push(el("div", { class: "field check" }, [box, el("label", { for: "lockdown" }, ["Also apply the lockdown profile"])]), el("p", { id: "lockdown-help", class: "help" }, [LOCKDOWN_HELP]));
  }
  nodes.push(...planNodes("Connection settings", p.setup));
  if (p.lockdown) nodes.push(...planNodes("Lockdown profile", p.lockdown));
  nodes.push(el("div", { class: "actions-inline" }, [button("Connect", () => void apply(c, lockdown), true), button("Back", () => void load())]));
  show(nodes);
  enter(`Connect ${c.name}`);
}

function renderOutcome(c: Client, o: Outcome, removing: boolean): void {
  if (o.ok) {
    const title = heading(removing ? `${c.name} is disconnected` : `${c.name} is connected`);
    const nodes: Node[] = [
      title,
      el("p", {}, [removing ? "Its settings files are restored to how they were before setup." : "Restart the agent so that it reads the new settings. Its tool calls then go through the Gateway."]),
    ];
    if (o.output) nodes.push(el("pre", { class: "output", tabindex: "0", "aria-label": "Output of smcpctl" }, [o.output.trimEnd()]));
    nodes.push(el("div", { class: "actions-inline" }, [button("Back to the List", () => void load(), true)]));
    show(nodes);
    enter(removing ? `${c.name} is disconnected` : `${c.name} is connected`);
    return;
  }
  const code = o.code ?? (removing ? "CLIENT_REMOVE_FAILED" : "CLIENT_SETUP_FAILED");
  show([...messageNodes(code, { client: c.id }), detailsArea(o), el("div", { class: "actions-inline" }, [button("Back to the List", () => void load(), true)])]);
  enter(message(cat, code, { client: c.id }).title);
}

function busy(text: string): void {
  show([heading(text), el("p", { class: "muted" }, ["Running smcpctl."])], true);
  enter(text);
}

// ---- Commands ----

async function load(): Promise<void> {
  if (demoMode) return renderList(DEMO_VIEW[q.get("demo") ?? ""] ?? DEMO_VIEW.list!);
  const v = await invoke<ClientsView>("clients_list");
  if (v) renderList(v);
}

async function preview(c: Client, lockdown: boolean): Promise<void> {
  if (demoMode) return renderPreview(c, demoPreview(c, lockdown), lockdown);
  busy(`Reading the changes for ${c.name}`);
  try {
    const p = await invoke<Preview>("clients_preview", { id: c.id, lockdown });
    if (p) renderPreview(c, p, lockdown);
  } catch (err) {
    renderOutcome(c, err as Outcome, false);
  }
}

async function apply(c: Client, lockdown: boolean): Promise<void> {
  busy(`Connecting ${c.name}`);
  const o = await invoke<Outcome>("clients_apply", { id: c.id, lockdown });
  if (o) renderOutcome(c, o, false);
}

async function remove(c: Client): Promise<void> {
  busy(`Disconnecting ${c.name}`);
  const o = await invoke<Outcome>("clients_remove", { id: c.id });
  if (o) renderOutcome(c, o, true);
}

// Readings the accessibility test renders without the application:
// clients.html?demo=list|none-connected|none-detected|not-set-up|failed[&preview=<id>]
const ALL: Client[] = [
  { id: "claude-code", name: "Claude Code", installed: true, connected: true, lockdown: true, lockdownAvailable: true },
  { id: "codex", name: "Codex CLI", installed: true, connected: false, lockdown: false, lockdownAvailable: true },
  { id: "gemini-cli", name: "Gemini CLI", installed: false, connected: false, lockdown: false, lockdownAvailable: true },
  { id: "goose", name: "Goose", installed: false, connected: false, lockdown: false, lockdownAvailable: true },
];
const DEMO_VIEW: Record<string, ClientsView> = {
  list: { gatewaySetUp: true, smcpctl: true, clients: ALL },
  "none-connected": { gatewaySetUp: true, smcpctl: true, clients: ALL.map((c) => ({ ...c, connected: false, lockdown: false })) },
  "none-detected": { gatewaySetUp: true, smcpctl: true, clients: ALL.map((c) => ({ ...c, installed: false, connected: false })) },
  "not-set-up": { gatewaySetUp: false, smcpctl: true, clients: [] },
  failed: {
    gatewaySetUp: true,
    smcpctl: true,
    clients: [],
    failure: { ok: false, code: "CLIENTS_DETECT_FAILED", command: "smcpctl clients detect --json", detail: "smcpctl exited with status 2, which means it stopped at an error. Its output names the cause.", output: "smcpctl: unknown command\n" },
  },
};
function demoPreview(c: Client, lockdown: boolean): Preview {
  const setup: Plan = {
    changes: [{ path: "/home/user/.codex/config.toml", scope: "user", purpose: "MCP server entry for the Gateway", action: "update", content: '[mcp_servers.smcp]\ncommand = "/usr/bin/smcp-stdio"\n' }],
    commands: [],
    notes: [],
  };
  const lock: Plan = { changes: [{ path: "/etc/codex/requirements.toml", scope: "managed", purpose: "allow only the Gateway", action: "create", content: '[mcp_server_allowlist]\nsmcp = { command = "/usr/bin/smcp-stdio" }\n' }], commands: [], notes: [] };
  return { client: c.id, name: c.name, setup, lockdown: lockdown ? lock : null };
}

byId("close").addEventListener("click", () => window.close());
if (demoMode && q.has("preview")) {
  const c = ALL.find((x) => x.id === q.get("preview")) ?? ALL[1]!;
  void preview(c, true);
} else {
  load().catch(() => show([heading("Could not look for agents")]));
}
