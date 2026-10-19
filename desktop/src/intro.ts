// First-run introduction state machine (SRS FR-20.40, FR-20.41). Pure
// functions only: intro-view.ts renders a state and sends events; the Rust
// side stores the one flag that persisted() returns (FR-20.42).

export interface IntroState {
  step: number;
  total: number;
  status: "open" | "finished" | "skipped";
}

export type IntroEvent = { type: "next" | "back" | "skip" | "finish" | "reopen" };

/** The stored values of the introduction flag (FR-20.41). */
export const FLAG_COMPLETED = "completed";
export const FLAG_SKIPPED = "skipped";
export type IntroFlag = typeof FLAG_COMPLETED | typeof FLAG_SKIPPED;

/** FR-20.40: at most five steps. */
export const MAX_STEPS = 5;

export function start(total: number): IntroState {
  if (!Number.isInteger(total) || total < 1 || total > MAX_STEPS) {
    throw new RangeError(`an introduction has 1 to ${MAX_STEPS} steps, not ${total}`);
  }
  return { step: 0, total, status: "open" };
}

/**
 * Applies one event. A closed introduction ignores every event but reopen,
 * which starts again at the first step (FR-20.41).
 */
export function reduce(s: IntroState, e: IntroEvent): IntroState {
  if (e.type === "reopen") return { step: 0, total: s.total, status: "open" };
  if (s.status !== "open") return s;
  switch (e.type) {
    case "next":
      return s.step + 1 < s.total ? { ...s, step: s.step + 1 } : { ...s, status: "finished" };
    case "back":
      return s.step > 0 ? { ...s, step: s.step - 1 } : s;
    case "skip":
      return { ...s, status: "skipped" };
    case "finish":
      return { ...s, status: "finished" };
    default:
      return s;
  }
}

/** The flag to store for a state, or null while the introduction is open. */
export function persisted(s: IntroState): IntroFlag | null {
  if (s.status === "finished") return FLAG_COMPLETED;
  if (s.status === "skipped") return FLAG_SKIPPED;
  return null;
}

/** Whether the introduction opens at start, given the stored flag. */
export function showAtStart(flag: unknown): boolean {
  return flag !== FLAG_COMPLETED && flag !== FLAG_SKIPPED;
}

/** The text announced to screen readers for a step (FR-20.43). */
export function announcement(s: IntroState, steps: readonly { title: string }[]): string {
  return `Step ${s.step + 1} of ${s.total}: ${steps[s.step]?.title ?? ""}`;
}

export const isFirst = (s: IntroState): boolean => s.step === 0;
export const isLast = (s: IntroState): boolean => s.step === s.total - 1;
