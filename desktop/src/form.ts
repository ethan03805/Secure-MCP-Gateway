// Pure logic of the Settings window: the settings object the Rust side
// stores (src-tauri/src/settings.rs) and how its validation errors map to
// form fields. The Rust side validates; this file only shapes data.

export interface Settings {
  admin_url: string;
  metrics_address: string;
  ca_file: string;
  notifications: boolean;
  /** FR-20.14: off after installation. */
  start_at_login: boolean;
}

export interface SettingsView {
  settings: Settings;
  default_ca_file: string;
}

export interface FieldError {
  field: string;
  message: string;
}

export const FIELDS = ["admin_url", "metrics_address", "ca_file"] as const;
export type TextField = (typeof FIELDS)[number];

/** Reads the form values into a Settings object, trimming text fields. */
export function fromValues(values: Record<TextField, string>, notifications: boolean, startAtLogin = false): Settings {
  return {
    admin_url: values.admin_url.trim(),
    metrics_address: values.metrics_address.trim(),
    ca_file: values.ca_file.trim(),
    notifications,
    start_at_login: startAtLogin,
  };
}

/**
 * Groups errors by form field. Errors for a field the form does not have
 * (the settings file, the window) go to "form".
 */
export function errorsByField(errors: FieldError[]): Record<TextField | "form", string> {
  const out: Record<TextField | "form", string> = { admin_url: "", metrics_address: "", ca_file: "", form: "" };
  for (const e of errors) {
    const key: TextField | "form" = (FIELDS as readonly string[]).includes(e.field) ? (e.field as TextField) : "form";
    out[key] = out[key] ? `${out[key]} ${e.message}` : e.message;
  }
  return out;
}

/** Normalizes whatever the save command rejected with into field errors. */
export function toFieldErrors(err: unknown): FieldError[] {
  if (Array.isArray(err)) {
    return err.filter(
      (e): e is FieldError => typeof e === "object" && e !== null && typeof e.field === "string" && typeof e.message === "string",
    );
  }
  return [{ field: "form", message: typeof err === "string" ? err : "The settings could not be saved." }];
}
