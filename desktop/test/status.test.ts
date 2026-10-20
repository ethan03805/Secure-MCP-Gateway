// Tray state explanations from the shared catalogue (FR-20.45, FR-20.48).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { approvalsEmpty, explain, STATES, type Catalogue } from "../src/status-model.ts";

const catalogue = JSON.parse(readFileSync(new URL("../../docs/design/messages.json", import.meta.url), "utf8")) as Catalogue;

test("FR-20.45: each of the seven states has a meaning, an action and a control", () => {
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

test("FR-20.46: no pending approval shows its reason and next step from the catalogue", () => {
  const none = approvalsEmpty(catalogue, { state: "healthy", enforced: true, pending: 0 });
  assert.ok(none);
  assert.equal(none.title, "No approvals waiting");
  assert.match(none.what, /No tool call is waiting/);
  assert.ok(none.todo.length > 0);
  // A count, a stale reading or a stopped service shows no empty state.
  assert.equal(approvalsEmpty(catalogue, { state: "healthy", enforced: true, pending: 2 }), null);
  assert.equal(approvalsEmpty(catalogue, { state: "unreachable", enforced: true, pending: 0 }), null);
  assert.equal(approvalsEmpty(catalogue, { state: "stopped", enforced: true, pending: 0 }), null);
});

test("FR-20.45: the controls the requirement names", () => {
  const c = (state: string) => explain(catalogue, { state, enforced: true }).control;
  assert.equal(c("stopped"), "start");
  for (const s of ["fail-closed", "emergency-stop", "degraded", "running"]) assert.equal(c(s), "open-console", s);
});

test("a degraded Gateway that is not enforced explains the Standalone profile", () => {
  const x = explain(catalogue, { state: "degraded", enforced: false });
  assert.match(x.meaning, /Standalone/);
  assert.notEqual(x.meaning, explain(catalogue, { state: "degraded", enforced: true }).meaning);
});

test("a Standalone Gateway degraded only by its profile reads as running, not enforced", () => {
  const x = explain(catalogue, { state: "running", enforced: false });
  assert.equal(x.label, "Running");
  assert.equal(x.tone, "ok");
  assert.equal(x.notEnforced?.label, "not enforced");
  assert.doesNotMatch(x.meaning, /degraded/i);
  assert.match(x.meaning, /Standalone/);
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
