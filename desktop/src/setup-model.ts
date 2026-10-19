// First-run setup (SRS FR-20.8, FR-20.9, FR-20.46, FR-20.47). Pure
// functions: setup-view.ts renders them; the Rust side (setup.rs) runs
// `smcpctl install` and reports its progress. Wording follows
// docs/design/writing.md; tools/uilint checks it.

export type ProfileId = "standalone" | "enforced";
export type Role = "admin" | "approver";

/** The prerequisite check of the Enforced profile, as setup.rs reports it. */
export type Check = { result: "present" } | { result: "missing"; missing: string[] } | { result: "failed"; detail: string };

export interface ProfileInfo {
  id: ProfileId;
  /** Absent: offered without a check (Standalone). */
  check?: Check | null;
}

export interface Failure {
  code: string;
  retry: string;
  detail: string;
}

export interface Progress {
  state: "idle" | "running" | "succeeded" | "failed";
  profile?: ProfileId | null;
  bootstrapDone: boolean;
  serviceDone: boolean;
  output: string[];
  failure?: Failure | null;
}

export interface SetupInfo {
  os: string;
  configured: boolean;
  smcpctl?: string | null;
  profiles: ProfileInfo[];
  progress: Progress;
}

export interface Message {
  title: string;
  what: string;
  why?: string;
  todo: string;
}

export interface MessageCatalogue {
  desktop: { errors: Record<string, Message>; empty?: Record<string, Message> };
}

/** smcpctl's rule: 12 or more bytes (Go `len`), on one line, at most 1024. */
export const MIN_PASSWORD_BYTES = 12;
export const MAX_PASSWORD_BYTES = 1024;

export const ROLE_NAMES: Record<Role, string> = { admin: "Administrator", approver: "Approver" };

/** Help text of each profile choice (FR-20.46): what it does and when to choose it. */
export const PROFILE_TEXT: Record<ProfileId, { label: string; help: string }> = {
  standalone: {
    label: "Standalone",
    help: "The Gateway runs as a service of your account and checks, records and holds tool calls. Choose it on a Mac, on Windows, or on a Linux computer that lacks the Enforced prerequisites.",
  },
  enforced: {
    label: "Enforced",
    help: "The Gateway runs as system service accounts and starts each MCP server in a rootless Podman container with restricted network access. Choose it on a Linux computer you administer; installing it asks for an administrator's password.",
  },
};

/** FR-20.9: shown before installation on every platform. */
export const STANDALONE_STATEMENT =
  "The Standalone profile is labelled not enforced: MCP servers run as ordinary processes under your account, without container or network isolation. Policy checks, approvals and the Evidence Journal still work.";

/** Help text of each password (FR-20.46). */
export const PASSWORD_HELP: Record<Role, string> = {
  admin: "Signs in to the console to change policy, servers and settings. Use 12 or more characters.",
  approver: "Signs in to the console to approve or deny held tool calls and agent sign-ins. Use 12 or more characters and a different password from the Administrator's.",
};

/** The two steps setup shows (FR-20.8). */
export const STEPS = [
  { id: "bootstrap", label: "Create the keys, the configuration and the two accounts" },
  { id: "service", label: "Install and start the Gateway service" },
] as const;
export type StepId = (typeof STEPS)[number]["id"];
export type StepStatus = "waiting" | "running" | "done" | "failed";

export interface FieldError {
  field: string;
  code: string;
  role?: Role;
}

function bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** Checks the form before anything runs: the same rules smcpctl applies. */
export function validate(v: { admin: string; adminRepeat: string; approver: string; approverRepeat: string }): FieldError[] {
  const errors: FieldError[] = [];
  for (const role of ["admin", "approver"] as const) {
    const pw = v[role];
    const repeat = role === "admin" ? v.adminRepeat : v.approverRepeat;
    if (bytes(pw) < MIN_PASSWORD_BYTES) errors.push({ field: role, code: "SETUP_PASSWORD_TOO_SHORT", role });
    else if (bytes(pw) > MAX_PASSWORD_BYTES || /[\r\n\0]/.test(pw)) errors.push({ field: role, code: "SETUP_PASSWORD_INVALID", role });
    else if (pw !== repeat) errors.push({ field: `${role}Repeat`, code: "SETUP_PASSWORDS_DIFFER", role });
  }
  return errors;
}

/** Fills the {name} placeholders of a catalogue sentence. */
export function fill(s: string, vars: Record<string, string>): string {
  return s.replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m);
}

/** A catalogue message with its placeholders filled. */
export function message(c: MessageCatalogue, code: string, vars: Record<string, string> = {}): Message {
  const m = c.desktop.errors[code] ?? c.desktop.empty?.[code];
  if (!m) throw new RangeError(`the catalogue has no message ${code}`);
  const out: Message = { title: fill(m.title, vars), what: fill(m.what, vars), todo: fill(m.todo, vars) };
  if (m.why) out.why = fill(m.why, vars);
  return out;
}

/** The text of a field error, with the role named. */
export function fieldMessage(c: MessageCatalogue, e: FieldError): string {
  const m = message(c, e.code, { role: e.role ? ROLE_NAMES[e.role] : "" });
  return `${m.what} ${m.todo}`;
}

/** The status of each step for a progress report. */
export function stepStatus(p: Progress): Record<StepId, StepStatus> {
  if (p.state === "succeeded") return { bootstrap: "done", service: "done" };
  if (p.state === "idle") return { bootstrap: "waiting", service: "waiting" };
  const failed = p.state === "failed";
  if (!p.bootstrapDone) return { bootstrap: failed ? "failed" : "running", service: "waiting" };
  return { bootstrap: "done", service: failed ? "failed" : p.serviceDone ? "done" : "running" };
}

export const STEP_STATUS_TEXT: Record<StepStatus, string> = {
  waiting: "Waiting",
  running: "Running",
  done: "Done",
  failed: "Failed",
};

/** Whether the Enforced profile can be chosen, and the reason when not. */
export function enforcedChoice(p: ProfileInfo | undefined): { offered: boolean; missing: string[]; failed?: string } {
  if (!p) return { offered: false, missing: [] };
  const c = p.check;
  if (!c || c.result === "present") return { offered: true, missing: [] };
  if (c.result === "missing") return { offered: false, missing: c.missing };
  return { offered: false, missing: [], failed: c.detail };
}

/**
 * The details area of a failure (FR-20.47): the catalogue code, how the
 * command ended, the command to retry in a terminal and the output.
 */
export function details(f: Failure, output: readonly string[]): string {
  return [`Code: ${f.code}`, f.detail, "", "To retry in a terminal, run:", `  ${f.retry}`, "", "Output of smcpctl:", ...output].join("\n");
}

/** The view to show for a setup reading. */
export type Stage = "missing-smcpctl" | "configured" | "form" | "running" | "failed" | "done";

export function stage(info: SetupInfo): Stage {
  switch (info.progress.state) {
    case "running":
      return "running";
    case "failed":
      return "failed";
    case "succeeded":
      return "done";
  }
  if (info.configured) return "configured";
  if (!info.smcpctl) return "missing-smcpctl";
  return "form";
}
