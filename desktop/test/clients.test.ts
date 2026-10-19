// Client setup model (FR-20.10, FR-20.46, FR-20.47).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { changeLine, details, emptyState, fileCount, LOCKDOWN_HELP, noneConnected, partition, REMOVE_HELP, statusText, type Client, type ClientsView } from "../src/clients-model.ts";
import { message, type MessageCatalogue } from "../src/setup-model.ts";

const catalogue = JSON.parse(readFileSync(new URL("../../docs/design/messages.json", import.meta.url), "utf8")) as MessageCatalogue;
const c = (id: string, installed: boolean, connected = false): Client => ({ id, name: id, installed, connected, lockdown: false, lockdownAvailable: true });

test("FR-20.10: only detected clients are offered, the others are named", () => {
  const { found, others } = partition([c("claude-code", true), c("codex", true), c("goose", false)]);
  assert.deepEqual(found.map((x) => x.id), ["claude-code", "codex"]);
  assert.deepEqual(others.map((x) => x.id), ["goose"]);
  assert.equal(statusText(c("codex", true, true)), "Connected");
  assert.equal(statusText({ ...c("codex", true, true), lockdown: true }), "Connected, with the lockdown profile");
  assert.equal(statusText(c("codex", true)), "Not connected");
});

test("FR-20.46: each empty list says why and what to do next", () => {
  const v: ClientsView = { gatewaySetUp: true, smcpctl: true, clients: [c("claude-code", true)] };
  assert.equal(emptyState(v), null);
  assert.equal(noneConnected(v), true);
  assert.equal(noneConnected({ ...v, clients: [c("claude-code", true, true)] }), false);
  assert.equal(emptyState({ ...v, clients: [c("claude-code", false)] }), "CLIENTS_NONE_DETECTED");
  assert.equal(emptyState({ ...v, gatewaySetUp: false }), "CLIENTS_GATEWAY_NOT_SET_UP");
  assert.equal(emptyState({ ...v, smcpctl: false }), "SETUP_SMCPCTL_MISSING");
  assert.equal(emptyState({ ...v, failure: { ok: false, code: "CLIENTS_DETECT_FAILED", command: "", detail: "", output: "" } }), "CLIENTS_DETECT_FAILED");
  for (const code of ["CLIENTS_NONE_DETECTED", "CLIENTS_NONE_CONNECTED", "CLIENTS_GATEWAY_NOT_SET_UP", "CLIENTS_DETECT_FAILED", "CLIENT_PREVIEW_FAILED", "CLIENT_NOT_PREVIEWED", "CLIENT_UNKNOWN", "CLIENT_SETUP_FAILED", "CLIENT_REMOVE_FAILED"]) {
    const m = message(catalogue, code, { client: "codex" });
    assert.ok(m.what && m.todo, code);
    assert.ok(!/\{\w+\}/.test(m.what + m.todo), code);
  }
  assert.match(message(catalogue, "CLIENT_SETUP_FAILED", { client: "codex" }).what, /smcpctl connect codex/);
  for (const t of [LOCKDOWN_HELP, REMOVE_HELP]) assert.ok(t.split(/(?<=\.)\s+/).length <= 2, t);
});

test("FR-20.10: the preview names every file and counts each once", () => {
  const change = { path: "/h/.codex/config.toml", scope: "user", purpose: "MCP server entry", action: "update", content: "x" };
  assert.equal(changeLine(change), "Change /h/.codex/config.toml (your user settings): MCP server entry");
  assert.equal(changeLine({ ...change, action: "create", scope: "managed" }), "Create /h/.codex/config.toml (managed settings for this computer): MCP server entry");
  const p = { client: "codex", name: "Codex CLI", setup: { changes: [change], commands: [], notes: [] }, lockdown: { changes: [change, { ...change, path: "/etc/x" }], commands: [], notes: [] } };
  assert.equal(fileCount(p), 2);
  assert.equal(fileCount({ ...p, lockdown: null }), 1);
});

test("FR-20.47: failure details carry the code, the explanation, the command and the output", () => {
  const d = details({ ok: false, code: "CLIENT_SETUP_FAILED", command: "smcpctl connect codex --config /c", detail: "smcpctl exited with status 1, which means it stopped at an error.", output: "boom\n" });
  assert.match(d, /^Code: CLIENT_SETUP_FAILED$/m);
  assert.match(d, /^ {2}smcpctl connect codex --config \/c$/m);
  assert.ok(d.endsWith("boom"));
});
