// Control API client. The bearer token is held in sessionStorage for the
// tab only; the CSP forbids inline and third-party script, which is what
// keeps it out of reach of injected code.

export type Role = "administrator" | "approver";

export interface Credentials {
  token: string;
  role: Role;
  user: string;
  expiresAt: number;
}

const KEY = "smcp.console.credentials";

export function loadCredentials(): Credentials | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    const c = JSON.parse(raw) as Credentials;
    if (!c.token || c.expiresAt < Date.now()) {
      sessionStorage.removeItem(KEY);
      return null;
    }
    return c;
  } catch {
    return null;
  }
}

export function saveCredentials(c: Credentials | null): void {
  try {
    if (c) sessionStorage.setItem(KEY, JSON.stringify(c));
    else sessionStorage.removeItem(KEY);
  } catch {
    // Storage may be blocked; the session then lasts until reload.
  }
}

/** An error answer of the control API, or a network failure (status 0). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: unknown;
  constructor(status: number, code: string, message: string, body?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
  }
  /** The route is not served by this build (another element not merged yet). */
  get unavailable(): boolean {
    return (this.status === 404 && (this.code === "route_not_found" || this.code === "")) || (this.status === 405 && this.code === "");
  }
}

let current: Credentials | null = loadCredentials();
let onUnauthorized: (() => void) | null = null;

export function setCredentials(c: Credentials | null): void {
  current = c;
  saveCredentials(c);
}
export function credentials(): Credentials | null {
  return current;
}
export function setUnauthorizedHandler(f: () => void): void {
  onUnauthorized = f;
}

function headers(json: boolean): Headers {
  const h = new Headers({ Accept: "application/json" });
  if (json) h.set("Content-Type", "application/json");
  if (current) h.set("Authorization", `Bearer ${current.token}`);
  return h;
}

async function parse(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function toError(res: Response, body: unknown): ApiError {
  const e = (body as { error?: { code?: string; message?: string } } | null)?.error;
  if (e) return new ApiError(res.status, e.code ?? "", e.message ?? res.statusText, body);
  if (res.status === 404 || res.status === 405) return new ApiError(res.status, "", "This route is not served by this Gateway build.", body);
  return new ApiError(res.status, "", typeof body === "string" && body ? body.slice(0, 300) : res.statusText || "request failed", body);
}

export async function request<T>(method: "GET" | "POST", path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers: headers(method === "POST"),
      body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
      credentials: "omit",
      cache: "no-store",
      signal,
    });
  } catch (err) {
    if ((err as Error).name === "AbortError") throw err;
    throw new ApiError(0, "network", "The Gateway did not answer. Check that smcpd is running and that this page is open at the admin listener address.");
  }
  const parsed = await parse(res);
  if (!res.ok) {
    const e = toError(res, parsed);
    if (res.status === 401 && current && path !== "/admin/v1/login" && path !== "/api/v1/approvals/login") onUnauthorized?.();
    throw e;
  }
  return parsed as T;
}

export const get = <T>(path: string, signal?: AbortSignal) => request<T>("GET", path, undefined, signal);
export const post = <T>(path: string, body?: unknown) => request<T>("POST", path, body);

/** Downloads a GET response as a file with the bearer token attached. */
export async function download(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, { headers: headers(false), credentials: "omit", cache: "no-store" });
  if (!res.ok) throw toError(res, await parse(res));
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") ?? "";
  const m = /filename="([^"]+)"/.exec(cd);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = m?.[1] ?? fallbackName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export interface SSEMessage {
  event: string;
  data: string;
}

/**
 * Reads a text/event-stream with the bearer token (EventSource cannot send
 * an Authorization header). Reconnects with backoff until aborted.
 */
export function stream(path: string, onMessage: (m: SSEMessage) => void, onState: (open: boolean) => void): () => void {
  const ctl = new AbortController();
  let delay = 1000;
  const run = async () => {
    while (!ctl.signal.aborted) {
      try {
        const res = await fetch(path, { headers: headers(false), credentials: "omit", cache: "no-store", signal: ctl.signal });
        if (!res.ok || !res.body) {
          onState(false);
          if (res.status === 401 || res.status === 403 || res.status === 404) return;
          throw new Error(String(res.status));
        }
        onState(true);
        delay = 1000;
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let i: number;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const chunk = buf.slice(0, i);
            buf = buf.slice(i + 2);
            let event = "message";
            const data: string[] = [];
            for (const line of chunk.split("\n")) {
              if (line.startsWith("event:")) event = line.slice(6).trim();
              else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
            }
            if (data.length) onMessage({ event, data: data.join("\n") });
          }
        }
        onState(false);
      } catch {
        if (ctl.signal.aborted) return;
        onState(false);
      }
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, 15000);
    }
  };
  void run();
  return () => ctl.abort();
}
