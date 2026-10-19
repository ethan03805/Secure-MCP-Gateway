// First-run setup model (FR-20.8, FR-20.9, FR-20.46, FR-20.47).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  details,
  enforcedChoice,
  fieldMessage,
  message,
  PASSWORD_HELP,
  PROFILE_TEXT,
  STANDALONE_STATEMENT,
  stage,
  stepStatus,
  validate,
  type MessageCatalogue,
  type Progress,
  type SetupInfo,
} from "../src/setup-model.ts";

const catalogue = JSON.parse(readFileSync(new URL("../../docs/design/messages.json", import.meta.url), "utf8")) as MessageCatalogue;
const idle: Progress = { state: "idle", bootstrapDone: false, serviceDone: false, output: [] };

test("FR-20.8: passwords follow smcpctl's rules before anything runs", () => {
  const ok = { admin: "twelve chars", adminRepeat: "twelve chars", approver: "approver pass", approverRepeat: "approver pass" };
  assert.deepEqual(validate(ok), []);
  assert.deepEqual(validate({ ...ok, admin: "short", adminRepeat: "short" }), [{ field: "admin", code: "SETUP_PASSWORD_TOO_SHORT", role: "admin" }]);
  assert.deepEqual(validate({ ...ok, approverRepeat: "approver pasS" }), [{ field: "approverRepeat", code: "SETUP_PASSWORDS_DIFFER", role: "approver" }]);
  // Twelve bytes, as Go's len counts: four three-byte characters pass.
  assert.deepEqual(validate({ ...ok, admin: "€€€€", adminRepeat: "€€€€" }), []);
  assert.equal(validate({ ...ok, admin: "line\nbreak pw", adminRepeat: "line\nbreak pw" })[0]?.code, "SETUP_PASSWORD_INVALID");
});

test("FR-20.47: every setup code has a catalogue message, with the role filled", () => {
  for (const code of [
    "SETUP_PASSWORD_TOO_SHORT",
    "SETUP_PASSWORD_INVALID",
    "SETUP_PASSWORDS_DIFFER",
    "SETUP_SMCPCTL_MISSING",
    "SETUP_PROFILE_UNAVAILABLE",
    "SETUP_CHECK_FAILED",
    "SETUP_RUNNING",
    "SETUP_ALREADY_CONFIGURED",
    "SETUP_NOT_ALLOWED",
    "SETUP_BOOTSTRAP_FAILED",
    "SETUP_INSTALL_FAILED",
    "ELEVATION_DENIED",
  ]) {
    const m = message(catalogue, code, { role: "Approver" });
    assert.ok(m.title && m.what && m.todo, code);
    assert.ok(!/\{\w+\}/.test(m.what + m.todo + (m.why ?? "")), `${code} has an unfilled placeholder`);
  }
  assert.equal(
    fieldMessage(catalogue, { field: "approverRepeat", code: "SETUP_PASSWORDS_DIFFER", role: "approver" }),
    "The two entries for the Approver password are different. Type the same password in both fields.",
  );
  assert.throws(() => message(catalogue, "NO_SUCH_CODE"));
});

test("FR-20.47: the details area has the code, the explanation, the retry command and the output", () => {
  const d = details({ code: "SETUP_INSTALL_FAILED", retry: "smcpctl install --profile standalone", detail: "smcpctl install exited with status 1, which means it stopped at an error." }, ["a", "b"]);
  assert.match(d, /^Code: SETUP_INSTALL_FAILED$/m);
  assert.match(d, /^ {2}smcpctl install --profile standalone$/m);
  assert.match(d, /exited with status 1, which means/);
  assert.ok(d.endsWith("a\nb"));
});

test("FR-20.8: the two steps follow the progress", () => {
  assert.deepEqual(stepStatus(idle), { bootstrap: "waiting", service: "waiting" });
  assert.deepEqual(stepStatus({ ...idle, state: "running" }), { bootstrap: "running", service: "waiting" });
  assert.deepEqual(stepStatus({ ...idle, state: "running", bootstrapDone: true }), { bootstrap: "done", service: "running" });
  assert.deepEqual(stepStatus({ ...idle, state: "failed" }), { bootstrap: "failed", service: "waiting" });
  assert.deepEqual(stepStatus({ ...idle, state: "failed", bootstrapDone: true }), { bootstrap: "done", service: "failed" });
  assert.deepEqual(stepStatus({ ...idle, state: "succeeded" }), { bootstrap: "done", service: "done" });
});

test("FR-20.9: Enforced is offered only when every prerequisite is present, and each missing one is named", () => {
  assert.deepEqual(enforcedChoice({ id: "enforced", check: { result: "present" } }), { offered: true, missing: [] });
  assert.deepEqual(enforcedChoice({ id: "enforced", check: { result: "missing", missing: ["podman"] } }), { offered: false, missing: ["podman"] });
  assert.equal(enforcedChoice({ id: "enforced", check: { result: "failed", detail: "x" } }).offered, false);
  assert.equal(enforcedChoice(undefined).offered, false);
  // The Standalone statement says "not enforced" and that servers are not contained.
  assert.match(STANDALONE_STATEMENT, /not enforced/);
  assert.match(STANDALONE_STATEMENT, /without container or network isolation/);
});

test("FR-20.46: each profile and password has help of at most two sentences", () => {
  for (const t of [...Object.values(PROFILE_TEXT).map((p) => p.help), ...Object.values(PASSWORD_HELP)]) {
    const sentences = t.split(/(?<=\.)\s+/).filter(Boolean);
    assert.ok(sentences.length >= 1 && sentences.length <= 2, t);
  }
});

test("FR-20.8: setup is offered only when no configuration exists", () => {
  const base: SetupInfo = { os: "macos", configured: false, smcpctl: "/usr/local/bin/smcpctl", profiles: [{ id: "standalone" }], progress: idle };
  assert.equal(stage(base), "form");
  assert.equal(stage({ ...base, configured: true }), "configured");
  assert.equal(stage({ ...base, smcpctl: null }), "missing-smcpctl");
  assert.equal(stage({ ...base, progress: { ...idle, state: "running" } }), "running");
  assert.equal(stage({ ...base, configured: true, progress: { ...idle, state: "succeeded" } }), "done");
  assert.equal(stage({ ...base, progress: { ...idle, state: "failed" } }), "failed");
});
