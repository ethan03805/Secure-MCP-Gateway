// The bundled ContextForge choice of the first-run setup (SRS FR-22.44,
// desktop part). The terminal setup asks the same question
// (cmd/smcpctl/contextforge_setup.go); test/contextforge-choice.test.ts
// keeps the two texts in step. The default is not to enable it: the box
// starts unchecked, and only a checked box adds --with-contextforge to
// `smcpctl install`, which then writes `[contextforge] bundled = true` and
// fetches the pinned image. Otherwise install writes `bundled = false`.
import { el } from "./dom.ts";

export const CONTEXTFORGE_TEXT = {
  legend: "Bundled ContextForge instance (optional)",
  label: "Enable the bundled ContextForge instance",
  adds: "Adds: hosted servers from the IBM ContextForge catalog, reached only through the Gateway.",
  risk: "Risk: a large third-party service runs on this host, and the code of hosted servers cannot be inspected.",
} as const;

/** The id of the checkbox in the setup form. */
export const CONTEXTFORGE_INPUT_ID = "contextforge";

/** The setup_run argument for the box's state; anything but true is no. */
export function contextforgeArgument(checked: unknown): boolean {
  return checked === true;
}

/** The fieldset the setup form shows, with the box unchecked. */
export function contextforgeField(): HTMLElement {
  const input = el("input", { type: "checkbox", id: CONTEXTFORGE_INPUT_ID, name: CONTEXTFORGE_INPUT_ID, "aria-describedby": "contextforge-adds contextforge-risk" });
  return el("fieldset", {}, [
    el("legend", {}, [CONTEXTFORGE_TEXT.legend]),
    el("div", { class: "field choice" }, [
      input,
      el("div", {}, [
        el("label", { for: CONTEXTFORGE_INPUT_ID }, [CONTEXTFORGE_TEXT.label]),
        el("p", { id: "contextforge-adds", class: "help" }, [CONTEXTFORGE_TEXT.adds]),
        el("p", { id: "contextforge-risk", class: "help" }, [CONTEXTFORGE_TEXT.risk]),
      ]),
    ]),
  ]);
}

/** Whether the operator checked the box in the current form. */
export function contextforgeChecked(): boolean {
  const n = document.getElementById(CONTEXTFORGE_INPUT_ID);
  return contextforgeArgument(n instanceof HTMLInputElement ? n.checked : false);
}
