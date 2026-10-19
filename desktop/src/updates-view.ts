// The Check for Updates window (FR-20.11 to FR-20.13). It calls only the
// commands its capability grants (capabilities/updates.json).
import { catalogue } from "./catalogue.js";
import { plan, PREVIEWS, type Shown, type UpdatesView } from "./updates-model.ts";
import { byId, el, invoke } from "./dom.ts";

function showMessage(m: Shown | undefined, isError: boolean): void {
  const box = byId("message");
  if (!m) {
    box.replaceChildren();
    return;
  }
  const parts: HTMLElement[] = [el("h2", {}, [m.title]), el("p", {}, [m.what])];
  if (m.why) parts.push(el("p", {}, [m.why]));
  parts.push(el("p", {}, [m.todo]));
  if (isError) {
    const pre = el("pre", { class: "log mono" }, [m.details]);
    const copy = el("button", { type: "button" }, ["Copy Details"]);
    copy.addEventListener("click", () => void navigator.clipboard?.writeText(`${m.code}\n${m.details}`));
    parts.push(el("details", {}, [el("summary", {}, [`Details (${m.code})`]), pre, copy]));
  }
  const div = el("div", isError ? { class: "message", role: "alert" } : { class: "message" }, parts);
  box.replaceChildren(div);
}

let shownKey = "";

function render(v: UpdatesView): void {
  const key = JSON.stringify(v);
  if (key === shownKey) return;
  shownKey = key;
  const p = plan(catalogue, v);
  byId("main").setAttribute("aria-busy", String(p.busy));
  byId("status").textContent = p.status;
  showMessage(p.message, p.isError);
  const dl = byId("facts");
  dl.replaceChildren(...p.facts.flatMap(([k, val]) => [el("dt", {}, [k]), el("dd", {}, [val])]));
  byId("app-update").hidden = !p.appUpdate;
  byId("app-kind").textContent = v.appKind ?? "installer";
  const ab = byId("app-blocked");
  ab.hidden = !p.appBlocked;
  ab.textContent = p.appBlocked ?? "";
  byId("gateway-upgrade").hidden = !p.gatewayUpgrade;
  const gb = byId("gateway-blocked");
  gb.hidden = !p.gatewayBlocked;
  gb.textContent = p.gatewayBlocked ?? "";
  for (const id of ["update-app", "upgrade-gateway"]) (byId(id) as HTMLButtonElement).disabled = p.busy;
  (byId("check") as HTMLButtonElement).disabled = !p.canCheck;
  byId("notes").hidden = !p.canOpenNotes;
  byId("progress").hidden = v.log.length === 0;
  byId("log").textContent = v.log.join("\n");
}

async function refresh(): Promise<void> {
  try {
    const v = await invoke<UpdatesView>("updates_get");
    if (v) render(v);
  } catch {
    // The next refresh tries again.
  }
}

async function upgradeGateway(): Promise<void> {
  const input = byId("passphrase") as HTMLInputElement;
  const err = byId("passphrase-error");
  if (!input.value) {
    input.setAttribute("aria-invalid", "true");
    err.textContent = "Enter the backup passphrase.";
    input.focus();
    return;
  }
  input.setAttribute("aria-invalid", "false");
  err.textContent = "";
  const passphrase = input.value;
  input.value = "";
  await invoke("updates_upgrade_gateway", { passphrase });
  void refresh();
}

byId("check").addEventListener("click", () => void invoke("updates_check").then(refresh));
byId("notes").addEventListener("click", () => void invoke("updates_open_notes"));
byId("update-app").addEventListener("click", () => void invoke("updates_install_app").then(refresh));
byId("upgrade-gateway").addEventListener("click", () => void upgradeGateway());
byId("close").addEventListener("click", () => window.close());

const preview = new URLSearchParams(location.search).get("preview");
if (preview !== null) {
  // The accessibility test renders a fixed state without the application.
  const v = PREVIEWS[preview];
  if (!v) throw new RangeError(`no preview ${preview}`);
  render(v);
} else {
  void refresh();
  setInterval(() => void refresh(), 1000);
}
byId("title").focus();
