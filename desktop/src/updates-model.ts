// The Check for Updates window (SRS FR-20.11 to FR-20.13): what to show for
// the state the Rust side reports (src-tauri/src/updates.rs). Errors and
// the empty state take their text from the shared message catalogue
// docs/design/messages.json (FR-20.46 to FR-20.48). Pure functions.

export interface CatalogueMessage {
  title: string;
  what: string;
  why?: string;
  todo: string;
}

export interface MessageCatalogue {
  desktop: {
    errors: Record<string, CatalogueMessage>;
    empty: Record<string, CatalogueMessage>;
  };
}

export type Phase = "idle" | "checking" | "latest" | "available" | "working" | "installer-started" | "upgraded" | "failed";

export interface UpdateMessage {
  code: string;
  params: Record<string, string>;
  details: string;
}

/** The Rust side's View, field for field. */
export interface UpdatesView {
  phase: Phase;
  installed: string;
  latest?: string | null;
  appNewer: boolean;
  notes: boolean;
  appKind?: string | null;
  appBlocked?: string | null;
  gateway?: string | null;
  gatewayUpgradable: boolean;
  gatewayBlocked?: string | null;
  log: string[];
  message?: UpdateMessage | null;
}

/** A catalogue message with its placeholders filled. */
export interface Shown {
  code: string;
  title: string;
  what: string;
  why?: string;
  todo: string;
  details: string;
}

/** Replaces {name} with params[name]; an unknown name stays visible. */
export function fill(text: string, params: Record<string, string>): string {
  return text.replace(/\{([a-z]+)\}/g, (m, k: string) => params[k] ?? m);
}

export function shown(cat: MessageCatalogue, kind: "errors" | "empty", code: string, params: Record<string, string>, details = ""): Shown {
  const m = cat.desktop[kind][code];
  if (!m) throw new RangeError(`the catalogue has no desktop.${kind}.${code}`);
  return {
    code,
    title: fill(m.title, params),
    what: fill(m.what, params),
    why: m.why === undefined ? undefined : fill(m.why, params),
    todo: fill(m.todo, params),
    details,
  };
}

/** What the window shows for a state. */
export interface Plan {
  /** One sentence about where things stand, or none when a message says it. */
  status: string;
  /** The error, or the empty state "This is the latest version". */
  message?: Shown;
  /** The message is an error (role="alert") rather than an empty state. */
  isError: boolean;
  busy: boolean;
  canCheck: boolean;
  canOpenNotes: boolean;
  /** Update App is offered. */
  appUpdate: boolean;
  /** Why the app cannot update itself, when a newer release exists. */
  appBlocked?: string;
  /** Upgrade Gateway is offered. */
  gatewayUpgrade: boolean;
  /** Why the Gateway cannot be upgraded here, when that matters. */
  gatewayBlocked?: string;
  facts: [string, string][];
}

function newer(a: string, b: string): boolean {
  const p = (s: string) => s.split(/[.+-]/).slice(0, 3).map((x) => Number(x));
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < 3; i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d > 0;
  }
  return false;
}

export function plan(cat: MessageCatalogue, v: UpdatesView): Plan {
  const busy = v.phase === "checking" || v.phase === "working";
  const latest = v.latest ?? undefined;
  const gatewayOlder = Boolean(latest && v.gateway && newer(latest, v.gateway));
  const facts: [string, string][] = [["This app", v.installed]];
  if (v.gateway) facts.push(["Gateway", v.gateway]);
  if (latest) facts.push(["Newest release", latest]);
  const out: Plan = {
    status: "",
    isError: false,
    busy,
    canCheck: !busy,
    canOpenNotes: v.notes && !busy,
    appUpdate: false,
    gatewayUpgrade: false,
    facts,
  };
  switch (v.phase) {
    case "idle":
      out.status = "Select Check Now to look for a newer release.";
      break;
    case "checking":
      out.status = "Checking GitHub for a newer release.";
      break;
    case "latest":
      out.message = shown(cat, "empty", "UPDATES_NONE", { version: latest ?? v.installed });
      break;
    case "available": {
      const parts = [`Version ${latest} is available.`];
      if (v.appNewer) parts.push(`This app is version ${v.installed}.`);
      if (gatewayOlder) parts.push(`The Gateway is version ${v.gateway}.`);
      out.status = parts.join(" ");
      break;
    }
    case "working":
      out.status = "Downloading and verifying the release. Nothing is installed until every check passes.";
      break;
    case "installer-started":
      out.status = "The verified installer has started. The app closes or restarts in a few seconds so that the new version runs.";
      break;
    case "upgraded":
      out.status = `The Gateway was upgraded to version ${v.gateway ?? latest}.`;
      break;
    case "failed":
      break;
  }
  if (v.message) {
    out.message = shown(cat, "errors", v.message.code, v.message.params, v.message.details);
    out.isError = true;
  }
  const settled = v.phase === "available" || v.phase === "failed";
  if (settled && v.appNewer) {
    if (v.appKind) out.appUpdate = true;
    else out.appBlocked = v.appBlocked ?? undefined;
  }
  if (settled && gatewayOlder) {
    if (v.gatewayUpgradable) out.gatewayUpgrade = true;
    else out.gatewayBlocked = v.gatewayBlocked ?? undefined;
  }
  return out;
}

/** Fixed states for the accessibility test (e2e/a11y.mjs), by name. */
export const PREVIEWS: Record<string, UpdatesView> = {
  idle: { phase: "idle", installed: "1.3.0", appNewer: false, notes: false, gatewayUpgradable: false, log: [] },
  latest: { phase: "latest", installed: "1.3.0", latest: "1.3.0", appNewer: false, notes: false, gateway: "1.3.0", gatewayUpgradable: true, log: [] },
  available: {
    phase: "available",
    installed: "1.3.0",
    latest: "1.4.0",
    appNewer: true,
    notes: true,
    appKind: "macOS package (.pkg)",
    gateway: "1.3.0",
    gatewayUpgradable: true,
    log: [],
  },
  working: {
    phase: "working",
    installed: "1.3.0",
    latest: "1.4.0",
    appNewer: true,
    notes: true,
    appKind: "macOS package (.pkg)",
    gatewayUpgradable: false,
    log: ["Downloading smcp_1.4.0_darwin_arm64.pkg from release v1.4.0."],
  },
  "verify-failed": {
    phase: "failed",
    installed: "1.3.0",
    latest: "1.4.0",
    appNewer: true,
    notes: true,
    appKind: "macOS package (.pkg)",
    gatewayUpgradable: false,
    log: [],
    message: { code: "UPDATE_VERIFY_FAILED", params: { check: "SHA-256 checksum" }, details: "checksum mismatch for smcp_1.4.0_darwin_arm64.pkg" },
  },
  "rolled-back": {
    phase: "failed",
    installed: "1.4.0",
    latest: "1.4.0",
    appNewer: false,
    notes: true,
    gateway: "1.3.0",
    gatewayUpgradable: true,
    log: ["upgrade: upgrading from 1.3.0 to 1.4.0", "upgrade: rolling back: migration failed"],
    message: { code: "UPGRADE_ROLLED_BACK", params: { version: "1.3.0" }, details: "smcpctl: upgrade rolled back: migration failed; the previous version is running" },
  },
  offline: {
    phase: "failed",
    installed: "1.3.0",
    appNewer: false,
    notes: false,
    gatewayUpgradable: false,
    log: [],
    message: { code: "UPDATE_CHECK_FAILED", params: {}, details: "network: Connection refused" },
  },
};
