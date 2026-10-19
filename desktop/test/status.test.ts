// Tray state explanations from the shared catalogue (FR-20.45, FR-20.48).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { explain, STATES, type Catalogue } from "../src/status-model.ts";

const catalogue = JSON.parse(readFileSync(new URL("../../docs/design/messages.json", import.meta.url), "utf8")) as Catalogue;

test("FR-20.45: each of the six states has a meaning, an action and a control", () => {
  for (const state of STATES) {
    for (const enforced of [true, false]) {
      const x = explain(catalogue, { state, enforced, lastReading: "14:02:11" });
      assert.ok(x.label && x.meaning && x.action, state);
      assert.ok(["open-console", "start", "restart"].includes(x.control), state);
      const known = state !== "stopped" && state !== "unreachable";
      assert.equal(Boolean(x.notEnforced), !enforced && known, state);
    }
  }
});

test("FR-20.45: the controls the requirement names", () => {
  const c = (state: string) => explain(catalogue, { state, enforced: true }).control;
  assert.equal(c("stopped"), "start");
  for (const s of ["fail-closed", "emergency-stop", "degraded"]) assert.equal(c(s), "open-console", s);
});

test("a degraded Gateway that is not enforced explains the Standalone profile", () => {
  const x = explain(catalogue, { state: "degraded", enforced: false });
  assert.match(x.meaning, /Standalone/);
  assert.notEqual(x.meaning, explain(catalogue, { state: "degraded", enforced: true }).meaning);
});

test("FR-20.4, FR-20.45: unreachable never reads as healthy and shows the last reading", () => {
  const x = explain(catalogue, { state: "unreachable", enforced: true, lastReading: "14:02:11" });
  assert.notEqual(x.label, explain(catalogue, { state: "healthy", enforced: true }).label);
  assert.equal(x.tone, "idle");
  assert.match(x.detail ?? "", /14:02:11/);
  assert.match(explain(catalogue, { state: "unreachable", enforced: true }).detail ?? "", /none yet/);
});

test("an unknown state is an error, not a guess", () => {
  assert.throws(() => explain(catalogue, { state: "fine", enforced: true }), RangeError);
});
