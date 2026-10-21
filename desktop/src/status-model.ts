// Tray state explanations (SRS FR-20.45), from the shared message catalogue
// docs/design/messages.json (FR-20.48). Pure functions; the tray menu's
// status line (in Rust, from the same catalogue) and the status window use
// the same entries.

/**
 * The seven tray states of FR-20.2, as the Rust side names them. "running"
 * is a Standalone Gateway degraded only by its profile's own cause
 * (smcp_health_profile_only, FR-20.5): shown as "Running, not enforced".
 */
export const STATES = ["healthy", "running", "degraded", "fail-closed", "emergency-stop", "stopped", "unreachable"] as const;
export type TrayState = (typeof STATES)[number];
export type Control = "open-console" | "start" | "restart";
export type Tone = "ok" | "warn" | "bad" | "idle";

const TONES: Record<TrayState, Tone> = {
  healthy: "ok",
  running: "ok",
  degraded: "warn",
  "fail-closed": "bad",
  "emergency-stop": "bad",
  stopped: "idle",
  unreachable: "idle",
};

/** Whether a state comes from a fresh metrics reading. */
const READING: Record<TrayState, boolean> = {
  healthy: true,
  running: true,
  degraded: true,
  "fail-closed": true,
  "emergency-stop": true,
  stopped: false,
  unreachable: false,
};

export interface StateText {
  label: string;
  meaning: string;
  action: string;
  detail?: string;
  control: Control;
}

export interface Catalogue {
  desktop: {
    states: Record<string, StateText>;
    labels: Record<string, { label: string; meaning: string }>;
    empty?: Record<string, { title: string; what: string; todo: string }>;
  };
}

/**
 * The empty state of the status window's approvals count (FR-20.46): with
 * a fresh reading of no pending approval, APPROVALS_NONE's title, reason
 * and next step; otherwise none (a count is shown, or no reading).
 */
export function approvalsEmpty(c: Catalogue, h: Health): { title: string; what: string; todo: string } | null {
  const state = (STATES as readonly string[]).includes(h.state) ? (h.state as TrayState) : "unreachable";
  if (h.pending !== 0 || !READING[state]) return null;
  const e = c.desktop.empty?.["APPROVALS_NONE"];
  if (!e) throw new Error("the catalogue has no desktop.empty.APPROVALS_NONE");
  return e;
}

export interface Health {
  state: string;
  enforced: boolean;
  lastReading?: string;
  pending?: number;
}

export interface Explanation {
  state: TrayState;
  tone: Tone;
  label: string;
  meaning: string;
  action: string;
  detail?: string;
  control: Control;
  notEnforced?: { label: string; meaning: string };
}

function isState(s: string): s is TrayState {
  return (STATES as readonly string[]).includes(s);
}

/**
 * The explanation of a health reading. A degraded Gateway that is not
 * labelled enforced uses the catalogue's degraded-not-enforced entry (a
 * cause besides the profile's own; the profile alone is "running"): a
 * Standalone installation is never healthy (FR-13.10).
 */
export function explain(catalogue: Catalogue, h: Health): Explanation {
  if (!isState(h.state)) throw new RangeError(`unknown tray state ${h.state}`);
  const key = h.state === "degraded" && !h.enforced ? "degraded-not-enforced" : h.state;
  const text = catalogue.desktop.states[key];
  if (!text) throw new RangeError(`the catalogue has no entry for ${key}`);
  return {
    state: h.state,
    tone: TONES[h.state],
    label: text.label,
    meaning: text.meaning,
    action: text.action,
    detail: text.detail?.replaceAll("{lastReading}", h.lastReading ?? "none yet"),
    control: text.control,
    // Stopped and unreachable carry no fresh reading, so the release label is
    // unknown and not shown (as beside the tray icon).
    notEnforced: h.enforced || !READING[h.state] ? undefined : catalogue.desktop.labels["not-enforced"],
  };
}

/** Button text of each control: the tray menu's own item names (FR-20.2). */
export const CONTROL_LABELS: Record<Control, string> = { "open-console": "Open Console", start: "Start", restart: "Restart" };
