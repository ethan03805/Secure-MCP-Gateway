// Small DOM and IPC helpers shared by the bundled windows.

interface TauriInternals {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
}

/**
 * Calls an application command. Each window's capability grants it only its
 * own commands (SR-2-5). Outside the application (the browser preview the
 * accessibility tests use) the call is reported as an "smcp-call" event.
 */
export function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T | undefined> {
  const internals = (window as unknown as { __TAURI_INTERNALS__?: TauriInternals }).__TAURI_INTERNALS__;
  if (internals) return internals.invoke<T>(cmd, args);
  document.dispatchEvent(new CustomEvent("smcp-call", { detail: { cmd, args } }));
  return Promise.resolve(undefined);
}

export function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element ${id}`);
  return el;
}

export function el(tag: string, attrs: Record<string, string> = {}, children: (Node | string)[] = []): HTMLElement {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  n.append(...children);
  return n;
}
