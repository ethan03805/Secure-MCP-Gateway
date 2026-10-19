// The Settings window. It calls only the two commands its capability
// grants (capabilities/settings.json): get_settings and save_settings.
import { errorsByField, FIELDS, fromValues, toFieldErrors, type Settings, type SettingsView, type TextField } from "./form.ts";

interface TauriInternals {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
}

function invoke<T>(cmd: "get_settings" | "save_settings", args?: Record<string, unknown>): Promise<T> {
  const internals = (window as unknown as { __TAURI_INTERNALS__?: TauriInternals }).__TAURI_INTERNALS__;
  if (!internals) return Promise.reject("This page runs only inside the desktop application.");
  return internals.invoke<T>(cmd, args);
}

function input(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLInputElement)) throw new Error(`missing input ${id}`);
  return el;
}

function show(errors: Record<TextField | "form", string>): void {
  for (const f of FIELDS) {
    const msg = errors[f];
    input(f).setAttribute("aria-invalid", msg ? "true" : "false");
    const el = document.getElementById(`${f}-error`);
    if (el) el.textContent = msg;
  }
  const status = document.getElementById("status");
  if (status) status.textContent = errors.form;
}

async function load(): Promise<void> {
  const view = await invoke<SettingsView>("get_settings");
  for (const f of FIELDS) input(f).value = view.settings[f];
  input("notifications").checked = view.settings.notifications;
  input("start_at_login").checked = view.settings.start_at_login;
  const def = document.getElementById("default_ca_file");
  if (def) def.textContent = view.default_ca_file;
}

async function save(ev: Event): Promise<void> {
  ev.preventDefault();
  const values = Object.fromEntries(FIELDS.map((f) => [f, input(f).value])) as Record<TextField, string>;
  const settings: Settings = fromValues(values, input("notifications").checked, input("start_at_login").checked);
  try {
    await invoke<void>("save_settings", { settings });
    show(errorsByField([]));
    const status = document.getElementById("status");
    if (status) status.textContent = "Saved.";
  } catch (err) {
    show(errorsByField(toFieldErrors(err)));
  }
}

document.getElementById("settings")?.addEventListener("submit", (ev) => void save(ev));
load().catch((err: unknown) => show(errorsByField(toFieldErrors(err))));
