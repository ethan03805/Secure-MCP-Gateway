// The Gateway Status window (FR-20.45): the tray state, what it means, what
// to do, and the control that does it.
import { catalogue } from "./catalogue.js";
import { CONTROL_LABELS, explain, type Control, type Health, type TrayState } from "./status-model.ts";
import { byId, el, invoke } from "./dom.ts";

const COMMANDS: Record<Control, string> = { "open-console": "status_open_console", start: "status_start", restart: "status_restart" };

// The shape of each state (docs/design/visual.md, "Tray states"), drawn in
// the state's color; the word beside it carries the meaning.
const SHAPES: Record<TrayState, string> = {
  healthy: '<rect x="1" y="1" width="10" height="10"/>',
  degraded: '<path d="M6 0.5 11.5 6 6 11.5 0.5 6Z"/>',
  "fail-closed": '<path d="M6 0.5 11.5 11 0.5 11Z"/>',
  "emergency-stop": '<path d="M6 0.5 11.5 9 0.5 9Z"/><rect x="0.5" y="10" width="11" height="1.5"/>',
  stopped: '<rect x="1.5" y="1.5" width="9" height="9" fill="none" stroke="currentColor" stroke-width="2"/>',
  unreachable: '<circle cx="6" cy="6" r="4.5" fill="none" stroke="currentColor" stroke-width="2"/>',
};

function shape(state: TrayState): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 12 12");
  svg.setAttribute("class", "shape");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "currentColor");
  // Fixed markup from SHAPES above, never page or Gateway data.
  svg.innerHTML = SHAPES[state];
  return svg;
}

let shown = "";

function render(h: Health): void {
  const key = JSON.stringify(h);
  if (key === shown) return;
  shown = key;
  const x = explain(catalogue, h);
  const line = byId("state-line");
  line.replaceChildren(el("span", { class: `state tone-${x.tone}` }, [shape(x.state), x.label]));
  if (x.notEnforced) line.append(el("span", { class: "label-chip" }, [x.notEnforced.label]));
  byId("meaning").textContent = x.meaning;
  byId("action").textContent = x.action;
  const b = el("button", { type: "button", class: "primary" }, [CONTROL_LABELS[x.control]]);
  b.addEventListener("click", () => void invoke(COMMANDS[x.control]));
  byId("controls").replaceChildren(b);
  byId("enforcement").replaceChildren(...(x.notEnforced ? [el("h2", {}, ["What not enforced means"]), el("p", {}, [x.notEnforced.meaning])] : []));
  const facts: [string, string][] = [];
  if (x.state === "unreachable") facts.push(["Last reading", h.lastReading ?? "none yet"]);
  if (typeof h.pending === "number" && x.state !== "unreachable" && x.state !== "stopped") facts.push(["Approvals waiting", String(h.pending)]);
  const dl = byId("facts");
  dl.replaceChildren(...facts.flatMap(([k, v]) => [el("dt", {}, [k]), el("dd", {}, [v])]));
  dl.hidden = facts.length === 0;
  document.title = `Gateway Status: ${x.label}`;
}

async function refresh(): Promise<void> {
  const h = await invoke<Health>("status_get");
  if (h) render(h);
}

const q = new URLSearchParams(location.search);
if (q.has("state")) {
  // The accessibility test renders a given reading without the application.
  render({ state: q.get("state") ?? "unreachable", enforced: q.get("enforced") === "1", lastReading: q.get("last") ?? undefined, pending: q.has("pending") ? Number(q.get("pending")) : undefined });
} else {
  void refresh();
  setInterval(() => void refresh(), 2000);
}
byId("close").addEventListener("click", () => window.close());
byId("title").focus();
