// The introduction state machine (FR-20.40, FR-20.41, FR-20.43).
import assert from "node:assert/strict";
import { test } from "node:test";
import { announcement, FLAG_COMPLETED, FLAG_SKIPPED, isFirst, isLast, MAX_STEPS, persisted, reduce, showAtStart, start, type IntroEvent, type IntroState } from "../src/intro.ts";
import { STEPS } from "../src/intro-steps.ts";

const run = (s: IntroState, ...types: IntroEvent["type"][]): IntroState => types.reduce((st, type) => reduce(st, { type }), s);
const at = (step: number): IntroState => {
  let s = start(4);
  for (let j = 0; j < step; j++) s = run(s, "next");
  return s;
};

test("FR-20.40: the introduction has one to five steps", () => {
  assert.ok(STEPS.length >= 1 && STEPS.length <= MAX_STEPS);
  assert.throws(() => start(0), RangeError);
  assert.throws(() => start(MAX_STEPS + 1), RangeError);
  assert.throws(() => start(2.5), RangeError);
});

test("next walks the steps and finishes after the last", () => {
  let s = start(4);
  assert.ok(isFirst(s));
  s = run(s, "next", "next", "next");
  assert.equal(s.step, 3);
  assert.ok(isLast(s));
  assert.equal(persisted(s), null);
  s = run(s, "next");
  assert.equal(s.status, "finished");
  assert.equal(persisted(s), FLAG_COMPLETED);
});

test("back stops at the first step", () => {
  const s = run(start(4), "back", "next", "back", "back");
  assert.equal(s.step, 0);
  assert.equal(s.status, "open");
});

test("FR-20.41: skip works from every step and is stored as skipped", () => {
  for (let i = 0; i < 4; i++) {
    const s = run(at(i), "skip");
    assert.equal(s.status, "skipped", `step ${i + 1}`);
    assert.equal(persisted(s), FLAG_SKIPPED);
  }
});

test("finish works from every step", () => {
  for (let i = 0; i < 4; i++) assert.equal(run(at(i), "finish").status, "finished");
});

test("a closed introduction ignores events until reopened", () => {
  const skipped = run(start(4), "next", "skip");
  assert.deepEqual(run(skipped, "next", "back", "finish"), skipped);
  const finished = run(start(4), "finish");
  assert.deepEqual(run(finished, "skip"), finished);
});

test("FR-20.41: reopen starts at the first step from any state", () => {
  for (const s of [run(start(4), "skip"), run(start(4), "finish"), at(2)]) {
    const r = run(s, "reopen");
    assert.deepEqual(r, { step: 0, total: 4, status: "open" });
    assert.equal(persisted(r), null);
  }
});

test("unknown events change nothing", () => {
  const s = start(3);
  assert.deepEqual(reduce(s, { type: "jump" } as unknown as IntroEvent), s);
});

test("FR-20.41: the introduction shows at start until it was completed or skipped", () => {
  for (const f of [undefined, null, "", "something else"]) assert.equal(showAtStart(f), true);
  assert.equal(showAtStart(FLAG_COMPLETED), false);
  assert.equal(showAtStart(FLAG_SKIPPED), false);
});

test("FR-20.43: each step announces its number, the count and its title", () => {
  let s = start(STEPS.length);
  for (let i = 0; i < STEPS.length; i++) {
    assert.equal(announcement(s, STEPS), `Step ${i + 1} of ${STEPS.length}: ${STEPS[i]?.title}`);
    s = run(s, "next");
  }
});

test("FR-20.40: the first step names the three tasks, and the steps offer their controls", () => {
  assert.equal(STEPS[0]?.tasks?.length, 3);
  const actions = STEPS.flatMap((st) => (st.actions ?? []).map((a) => a.action));
  for (const a of ["setup", "client-setup", "open-console"] as const) assert.ok(actions.includes(a), a);
});

test("FR-20.40: no step claims enforcement on a Mac", () => {
  const text = STEPS.flatMap((s) => [s.title, ...s.body, s.note ?? ""]).join(" ");
  assert.match(text, /not enforced/);
  assert.doesNotMatch(text, /\bis enforced\b|\bfully protect|\bsandboxed\b|\bisolated in containers\b/i);
});
