// The first-run setup window (SRS FR-20.8, FR-20.9, FR-20.15, FR-20.46,
// FR-20.47). It calls only the commands its capability grants
// (capabilities/setup.json). The passwords stay in the form fields until
// they are sent once to setup_run; the window never stores them.
import { catalogue } from "./catalogue.js";
import { byId, el, invoke } from "./dom.ts";
import {
  details,
  enforcedChoice,
  fieldMessage,
  message,
  PASSWORD_HELP,
  PROFILE_TEXT,
  ROLE_NAMES,
  STANDALONE_STATEMENT,
  stage,
  STEP_STATUS_TEXT,
  STEPS,
  stepStatus,
  validate,
  type FieldError,
  type MessageCatalogue,
  type ProfileId,
  type Progress,
  type Role,
  type SetupInfo,
  type Stage,
} from "./setup-model.ts";

const cat = catalogue as unknown as MessageCatalogue;
let info: SetupInfo | undefined;
let shownStage: Stage | "" = "";
/** After a failure, Try Again shows the form again. */
let retrying = false;
let poll: ReturnType<typeof setInterval> | undefined;

function announce(text: string): void {
  byId("announce").textContent = text;
}

/** Moves focus to a stage's heading so a screen reader reads it. */
function enter(heading: HTMLElement, title: string): void {
  document.title = `Set Up the Gateway: ${title}`;
  heading.focus();
  announce(title);
}

function heading(text: string): HTMLElement {
  return el("h2", { id: "stage-title", tabindex: "-1" }, [text]);
}

function show(nodes: Node[], busy = false): void {
  const s = byId("stage");
  s.replaceChildren(...nodes);
  s.setAttribute("aria-busy", String(busy));
}

/** An error or empty state from the catalogue (FR-20.46, FR-20.47). */
function messageBlock(code: string, vars: Record<string, string> = {}): HTMLElement[] {
  const m = message(cat, code, vars);
  const nodes = [heading(m.title), el("p", {}, [m.what])];
  if (m.why) nodes.push(el("p", {}, [m.why]));
  nodes.push(el("p", {}, [m.todo]));
  return nodes;
}

function button(label: string, onClick: () => void, primary = false): HTMLElement {
  const b = el("button", { type: "button", ...(primary ? { class: "primary" } : {}) }, [label]);
  b.addEventListener("click", onClick);
  return b;
}

function openConsole(): HTMLElement {
  return button("Open Console", () => void invoke("setup_open_console"));
}

function passwordField(id: string, label: string, help?: string): HTMLElement {
  const described = [help ? `${id}-help` : "", `${id}-error`].filter(Boolean).join(" ");
  const input = el("input", { id, name: id, type: "password", autocomplete: "new-password", spellcheck: "false", "aria-describedby": described, required: "" });
  return el("div", { class: "field" }, [
    el("label", { for: id }, [label]),
    input,
    ...(help ? [el("p", { id: `${id}-help`, class: "help" }, [help])] : []),
    el("p", { id: `${id}-error`, class: "error" }, []),
  ]);
}

function account(role: Role): HTMLElement {
  const name = ROLE_NAMES[role];
  return el("fieldset", {}, [
    el("legend", {}, [`${name} account`]),
    passwordField(role, `${name} password`, PASSWORD_HELP[role]),
    passwordField(`${role}Repeat`, `Repeat the ${name} password`),
  ]);
}

function profileOption(id: ProfileId, offered: boolean, extra: HTMLElement[] = []): HTMLElement {
  const input = el("input", { type: "radio", name: "profile", id: `profile-${id}`, value: id, "aria-describedby": `profile-${id}-help` });
  if (!offered) input.setAttribute("disabled", "");
  return el("div", { class: "field choice" }, [
    input,
    el("div", {}, [el("label", { for: `profile-${id}` }, [PROFILE_TEXT[id].label]), el("p", { id: `profile-${id}-help`, class: "help" }, [PROFILE_TEXT[id].help]), ...extra]),
  ]);
}

function renderForm(i: SetupInfo): void {
  const enforced = enforcedChoice(i.profiles.find((p) => p.id === "enforced"));
  const options = [profileOption("standalone", true)];
  if (i.profiles.some((p) => p.id === "enforced")) {
    const extra: HTMLElement[] = [];
    if (enforced.missing.length) {
      extra.push(el("p", { class: "help" }, ["Not offered on this computer. These prerequisites are missing:"]));
      extra.push(el("ul", { class: "help" }, enforced.missing.map((m) => el("li", {}, [m]))));
    } else if (enforced.failed !== undefined) {
      const m = message(cat, "SETUP_CHECK_FAILED");
      extra.push(el("p", { class: "help" }, [`${m.what} ${m.todo}`]));
    }
    options.push(profileOption("enforced", enforced.offered, extra));
  }
  const title = heading("Choose a profile and set two passwords");
  const form = el("form", { id: "setup-form", novalidate: "" }, [
    el("fieldset", {}, [el("legend", {}, ["Profile"]), ...options]),
    el("p", { class: "note", id: "standalone-statement" }, [STANDALONE_STATEMENT]),
    account("admin"),
    account("approver"),
    el("div", { class: "actions" }, [el("button", { type: "submit", class: "primary" }, ["Set Up the Gateway"])]),
    el("p", { id: "form-status", class: "error", role: "alert" }, []),
  ]);
  show([
    title,
    el("p", {}, [
      "Setup creates the Gateway's keys and its two console accounts, installs the Gateway as a service of this computer and starts it. It runs ",
      el("code", {}, ["smcpctl install"]),
      ", the command the terminal setup uses.",
    ]),
    form,
  ]);
  const standalone = document.getElementById("profile-standalone");
  if (standalone instanceof HTMLInputElement) standalone.checked = true;
  form.addEventListener("submit", (ev) => void submit(ev));
  enter(title, "Choose a profile and set two passwords");
}

function value(id: string): string {
  const n = document.getElementById(id);
  return n instanceof HTMLInputElement ? n.value : "";
}

function showFieldErrors(errors: FieldError[]): void {
  for (const id of ["admin", "adminRepeat", "approver", "approverRepeat"]) {
    const e = errors.find((x) => x.field === id);
    const input = document.getElementById(id);
    input?.setAttribute("aria-invalid", e ? "true" : "false");
    const p = document.getElementById(`${id}-error`);
    if (p) p.textContent = e ? fieldMessage(cat, e) : "";
  }
  const first = errors[0] && document.getElementById(errors[0].field);
  if (first instanceof HTMLElement) first.focus();
}

async function submit(ev: Event): Promise<void> {
  ev.preventDefault();
  const v = { admin: value("admin"), adminRepeat: value("adminRepeat"), approver: value("approver"), approverRepeat: value("approverRepeat") };
  const errors = validate(v);
  showFieldErrors(errors);
  if (errors.length) return;
  const checked = document.querySelector<HTMLInputElement>('input[name="profile"]:checked');
  const profile = (checked?.value ?? "standalone") as ProfileId;
  try {
    await invoke("setup_run", { profile, admin: v.admin, approver: v.approver });
  } catch (err) {
    const list = Array.isArray(err) ? (err as { code: string; role?: Role | null }[]) : [];
    const fields = list.filter((e) => e.role).map((e) => ({ field: e.role as Role, code: e.code, role: e.role as Role }));
    if (fields.length) {
      showFieldErrors(fields);
      return;
    }
    const code = list[0]?.code ?? "SETUP_BOOTSTRAP_FAILED";
    const m = message(cat, code);
    byId("form-status").textContent = `${m.title}. ${m.what} ${m.todo}`;
    return;
  }
  for (const id of ["admin", "adminRepeat", "approver", "approverRepeat"]) {
    const n = document.getElementById(id);
    if (n instanceof HTMLInputElement) n.value = "";
  }
  retrying = false;
  startPolling();
}

function stepList(p: Progress): HTMLElement {
  const status = stepStatus(p);
  return el(
    "ol",
    { class: "steps" },
    STEPS.map((s) => el("li", { class: `step-${status[s.id]}` }, [el("span", {}, [s.label]), el("span", { class: "step-status" }, [STEP_STATUS_TEXT[status[s.id]]])])),
  );
}

function output(lines: readonly string[]): HTMLElement {
  return el("pre", { class: "output", role: "log", tabindex: "0", "aria-label": "Output of smcpctl install" }, [lines.join("\n")]);
}

function renderRunning(p: Progress, first: boolean): void {
  if (!first) {
    // Update in place so focus and scroll stay where the user left them.
    const steps = document.querySelector(".steps");
    steps?.replaceWith(stepList(p));
    const out = document.querySelector<HTMLElement>("pre.output");
    if (out) {
      const atEnd = out.scrollTop + out.clientHeight >= out.scrollHeight - 4;
      out.textContent = p.output.join("\n");
      if (atEnd) out.scrollTop = out.scrollHeight;
    }
    return;
  }
  const title = heading("Setting up the Gateway");
  show([title, el("p", {}, ["This takes up to a few minutes. You can close this window; setup continues and the tray shows the Gateway's state."]), stepList(p), output(p.output)], true);
  enter(title, "Setting up the Gateway");
}

function renderFailed(p: Progress): void {
  const f = p.failure ?? { code: "SETUP_BOOTSTRAP_FAILED", retry: "smcpctl install --profile standalone", detail: "" };
  const nodes = messageBlock(f.code);
  const text = details(f, p.output);
  const copyStatus = el("span", { role: "status", class: "help" }, []);
  const copy = button("Copy Details", () => {
    navigator.clipboard?.writeText(text).then(
      () => (copyStatus.textContent = "Copied."),
      () => (copyStatus.textContent = "Select the text above and copy it."),
    );
  });
  nodes.push(
    stepList(p),
    el("details", { open: "" }, [
      el("summary", {}, ["Details"]),
      el("p", {}, ["To retry in a terminal, run:"]),
      el("pre", { class: "command", tabindex: "0", "aria-label": "Command to retry in a terminal" }, [f.retry]),
      el("pre", { class: "output", tabindex: "0", "aria-label": "Code and output of smcpctl install" }, [text]),
      el("div", { class: "actions-inline" }, [copy, copyStatus]),
    ]),
    el("div", { class: "actions-inline" }, [
      button(
        "Try Again",
        () => {
          retrying = true;
          if (info) renderForm(info);
          shownStage = "form";
        },
        true,
      ),
    ]),
  );
  show(nodes);
  const h = byId("stage-title");
  enter(h, message(cat, f.code).title);
}

function renderDone(p: Progress): void {
  const title = heading("The Gateway is set up");
  const nodes: Node[] = [title, stepList(p), el("p", {}, ["The Gateway service is running. The tray icon shows its state."])];
  if (p.profile !== "enforced") nodes.push(el("p", { class: "note" }, ["This installation is labelled not enforced. MCP servers run as ordinary processes under your account."]));
  nodes.push(
    el("h2", {}, ["Next"]),
    el("p", {}, ["Connect an agent with Set Up a Client, here or in the tray menu. Then sign in to the console with the Administrator or Approver password you chose."]),
    el("div", { class: "actions-inline" }, [button("Set Up a Client", () => void invoke("setup_open_client_setup"), true), openConsole()]),
  );
  show(nodes);
  enter(title, "The Gateway is set up");
}

function render(i: SetupInfo): void {
  info = i;
  let s = stage(i);
  if (retrying && s === "failed") s = "form";
  const changed = s !== shownStage;
  if (!changed && s !== "running") return;
  shownStage = s;
  switch (s) {
    case "form":
      renderForm(i);
      break;
    case "running":
      renderRunning(i.progress, changed);
      break;
    case "failed":
      renderFailed(i.progress);
      break;
    case "done":
      renderDone(i.progress);
      break;
    case "configured": {
      show([...messageBlock("SETUP_ALREADY_CONFIGURED"), el("div", { class: "actions-inline" }, [openConsole()])]);
      enter(byId("stage-title"), "The Gateway is already set up");
      break;
    }
    case "missing-smcpctl": {
      show(messageBlock("SETUP_SMCPCTL_MISSING"));
      enter(byId("stage-title"), "The Gateway commands are not installed");
      break;
    }
  }
  if (s !== "running" && poll) {
    clearInterval(poll);
    poll = undefined;
  }
}

function startPolling(): void {
  if (poll) return;
  const tick = async (): Promise<void> => {
    const p = await invoke<Progress>("setup_progress");
    if (p && info) render({ ...info, progress: p });
  };
  void tick();
  poll = setInterval(() => void tick(), 500);
}

// Readings the accessibility test renders without the application:
// setup.html?demo=form|form-enforced|form-missing|running|failed|done|configured|missing-smcpctl
const DEMO_OUTPUT = ["created directory /home/user/.config/smcp-gateway", "created keys and TLS certificates in /home/user/.local/state/smcp-gateway"];
function demo(name: string): SetupInfo {
  const idle: Progress = { state: "idle", bootstrapDone: false, serviceDone: false, output: [] };
  const base: SetupInfo = { os: "linux", configured: false, smcpctl: "/usr/bin/smcpctl", profiles: [{ id: "standalone" }], progress: idle };
  switch (name) {
    case "form-enforced":
      return { ...base, profiles: [{ id: "standalone" }, { id: "enforced", check: { result: "present" } }] };
    case "form-missing":
      return { ...base, profiles: [{ id: "standalone" }, { id: "enforced", check: { result: "missing", missing: ["podman", "kernel 6.8 or later (found 6.1.0)"] } }] };
    case "running":
      return { ...base, progress: { state: "running", profile: "standalone", bootstrapDone: false, serviceDone: false, output: DEMO_OUTPUT } };
    case "failed":
      return {
        ...base,
        progress: {
          state: "failed",
          profile: "standalone",
          bootstrapDone: true,
          serviceDone: false,
          output: [...DEMO_OUTPUT, "created configuration /home/user/.config/smcp-gateway/smcp.toml", "smcpctl: systemctl --user start smcpd.service: exit status 1"],
          failure: { code: "SETUP_INSTALL_FAILED", retry: "smcpctl install --profile standalone --metrics-port 9464 --notify off", detail: "smcpctl install exited with status 1, which means it stopped at an error. Its output below names the cause." },
        },
      };
    case "done":
      return { ...base, progress: { state: "succeeded", profile: "standalone", bootstrapDone: true, serviceDone: true, output: DEMO_OUTPUT } };
    case "configured":
      return { ...base, configured: true };
    case "missing-smcpctl":
      return { ...base, smcpctl: null };
    default:
      return base;
  }
}

byId("close").addEventListener("click", () => window.close());
const q = new URLSearchParams(location.search);
if (q.has("demo")) {
  render(demo(q.get("demo") ?? "form"));
} else {
  invoke<SetupInfo>("setup_get")
    .then((i) => {
      if (!i) return;
      render(i);
      if (i.progress.state === "running") startPolling();
    })
    .catch(() => {
      show(messageBlock("SETUP_NOT_ALLOWED"));
    });
}
