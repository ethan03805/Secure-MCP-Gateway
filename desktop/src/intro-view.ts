// The Introduction window (SRS FR-20.40 to FR-20.43). It calls only the
// commands its capability grants (capabilities/intro.json).
import { announcement, isFirst, isLast, persisted, reduce, start, type IntroState } from "./intro.ts";
import { STEPS, type GuideTopic, type IntroAction } from "./intro-steps.ts";
import { byId, el, invoke } from "./dom.ts";

/** The command each introduction control calls (fixed names, SR-2-5). */
const COMMANDS: Record<IntroAction, string> = {
  setup: "intro_open_setup",
  "client-setup": "intro_open_client_setup",
  "open-console": "intro_open_console",
};
const GUIDES: Partial<Record<IntroAction, GuideTopic>> = { setup: "setup", "client-setup": "connect" };

interface IntroInfo {
  /** The controls this version of the application offers. */
  available: IntroAction[];
}

const params = new URLSearchParams(location.search);
let state: IntroState = start(STEPS.length);
// The accessibility test opens a given step: intro.html?step=3 (1-based).
const want = Number(params.get("step"));
for (let i = 1; i < want && i <= STEPS.length; i++) state = reduce(state, { type: "next" });
// Outside the application every control counts as available unless the
// test names the missing ones: intro.html?unavailable=setup,client-setup.
let available = new Set<IntroAction>((["setup", "client-setup", "open-console"] as const).filter((a) => !(params.get("unavailable") ?? "").split(",").includes(a)));

function render(animate = true): void {
  const step = STEPS[state.step];
  if (!step) return;
  byId("step-count").textContent = `Introduction, step ${state.step + 1} of ${state.total}`;
  byId("step-title").textContent = step.title;
  const body = byId("step-body");
  body.replaceChildren(...step.body.map((p) => el("p", {}, [p])));
  if (step.tasks) {
    body.append(el("h2", {}, ["What you will do"]));
    body.append(el("ol", { class: "tasks" }, step.tasks.map((t) => el("li", {}, [el("div", {}, [el("strong", {}, [t.title]), el("span", {}, [t.text])])]))));
  }
  for (const a of step.actions ?? []) {
    const row = el("div", { class: "actions-inline" });
    const guide = GUIDES[a.action];
    if (available.has(a.action) || !a.unavailable || !guide) {
      const b = el("button", { type: "button" }, [a.label]);
      b.addEventListener("click", () => void invoke(COMMANDS[a.action]));
      row.append(b);
    } else {
      body.append(el("p", { class: "note" }, [a.unavailable]));
      const b = el("button", { type: "button" }, ["Open the Desktop Guide"]);
      b.addEventListener("click", () => void invoke("intro_open_guide", { topic: guide }));
      row.append(b);
    }
    body.append(row);
  }
  if (step.note) body.append(el("p", { class: "note" }, [step.note]));

  byId("back").hidden = isFirst(state);
  byId("next").textContent = isLast(state) ? "Done" : "Next";
  byId("progress").replaceChildren(...STEPS.map((_, i) => el("span", { class: i < state.step ? "done" : i === state.step ? "current" : "" })));

  // A short fade marks the change of step; style.css removes it under
  // reduced motion (FR-20.52).
  const main = byId("step");
  main.classList.remove("step-enter");
  if (animate) {
    void main.offsetWidth;
    main.classList.add("step-enter");
  }
  byId("announce").textContent = announcement(state, STEPS);
  document.title = `Introduction: ${step.title}`;
  // Focus goes to the heading so a screen reader reads the step (FR-20.43).
  byId("step-title").focus();
}

function send(type: "next" | "back" | "skip"): void {
  state = reduce(state, { type });
  const flag = persisted(state);
  if (flag) {
    void invoke("intro_close", { flag });
    return;
  }
  render();
}

byId("next").addEventListener("click", () => send("next"));
byId("back").addEventListener("click", () => send("back"));
byId("skip").addEventListener("click", () => send("skip"));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    e.preventDefault();
    send("skip");
  }
});

invoke<IntroInfo>("intro_get")
  .then((info) => {
    if (info) available = new Set(info.available);
  })
  .catch(() => undefined)
  .finally(() => render(false));
