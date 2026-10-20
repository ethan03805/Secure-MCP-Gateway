// The bundled ContextForge choice of the first-run setup (FR-22.44).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CONTEXTFORGE_TEXT, contextforgeArgument } from "../src/contextforge-choice.ts";

test("FR-22.44: the desktop note matches the terminal setup's, line for line", () => {
  const go = readFileSync(new URL("../../cmd/smcpctl/contextforge_setup.go", import.meta.url), "utf8");
  for (const line of [CONTEXTFORGE_TEXT.legend, CONTEXTFORGE_TEXT.adds, CONTEXTFORGE_TEXT.risk]) {
    assert.ok(go.includes(line), `smcpctl's question lacks: ${line}`);
  }
});

test("FR-22.44: only a checked box enables the bundled instance", () => {
  assert.equal(contextforgeArgument(true), true);
  for (const v of [false, undefined, null, "true", 1, "on"]) assert.equal(contextforgeArgument(v), false);
});

test("FR-22.44: the setup form starts with the box unchecked and sends its state", () => {
  const view = readFileSync(new URL("../src/setup-view.ts", import.meta.url), "utf8");
  assert.match(view, /contextforgeField\(\)/);
  assert.match(view, /contextforge: contextforgeChecked\(\)/);
  const mod = readFileSync(new URL("../src/contextforge-choice.ts", import.meta.url), "utf8");
  assert.doesNotMatch(mod, /checked: ""|setAttribute\("checked"|\.checked = true/);
});
