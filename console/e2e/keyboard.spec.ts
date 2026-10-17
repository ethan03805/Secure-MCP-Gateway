// FR-8.33 and FR-8.32 on intermediate states: console actions completed
// with keyboard events only, with axe (WCAG 2.2 A/AA) run on every state the
// flows pass through (sign-in, forms filled, dialogs open, results shown) in
// Chromium, Firefox and WebKit. WebKit moves Tab only between form controls
// by default (the macOS "keyboard navigation" setting); Option+Tab moves
// through every control there, so the WebKit run presses Alt+Tab. Every
// focus stop of the walk must show a focus indicator.
//
// The flows: sign-in; navigation by the view list; G-11 Session Approver
// create and remove (FR-2.23) and principal create, suspend and enable;
// G-01 emergency stop and resume; G-02 draft validate and diff; G-10 trust
// anchor enrollment with the fingerprint confirmation (FR-7.10) and
// removal; Escape closes a dialog and returns focus (no keyboard trap).
import AxeBuilder from "@axe-core/playwright";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { expect, test, type Locator, type Page } from "@playwright/test";
import { bin, work } from "./gateway";
import { claims, forget, g } from "./helpers";

test.describe.configure({ mode: "serial" });

let tabKey = "Tab";
let states = 0;

async function axe(page: Page, state: string) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(r.violations.map((v) => `${state}: ${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
  states++;
}

/**
 * Presses Tab, or Shift+Tab when the target comes before the focused element
 * in document order, until target has focus; every stop must show a focus
 * indicator.
 */
async function tabTo(page: Page, target: Locator, max = 400) {
  await expect(target).toBeVisible();
  const handle = await target.elementHandle();
  const trail: string[] = [];
  for (let i = 0; i < max; i++) {
    const st = await page.evaluate((t) => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return { at: false, back: false, ring: true, what: "body" };
      const s = getComputedStyle(el);
      // Headings focused after navigation (tabindex -1) are not Tab stops.
      const ring = el.tabIndex < 0 || (s.outlineStyle !== "none" && parseFloat(s.outlineWidth) >= 1) || s.boxShadow !== "none";
      const back = !!t && el !== t && !!(el.compareDocumentPosition(t) & Node.DOCUMENT_POSITION_PRECEDING);
      return { at: el === t, back, ring, what: `${el.tagName.toLowerCase()} "${(el.getAttribute("aria-label") || el.textContent || "").trim().slice(0, 30)}"` };
    }, handle);
    expect(st.ring, `no focus indicator on ${st.what}`).toBe(true);
    trail.push(st.what);
    if (st.at) return;
    await page.keyboard.press(st.back ? tabKey.replace("Tab", "Shift+Tab") : tabKey);
  }
  throw new Error(`Tab did not reach ${target}; last stops: ${trail.slice(-12).join(" > ")}`);
}

/**
 * Puts the sequential focus starting point at the top of the page, as a
 * person does by reloading or by tabbing in from the address bar: a
 * temporary button before every control is focused, and the next Tab leaves
 * it (it is removed then). The walk itself uses keyboard events only.
 */
async function fromTop(page: Page) {
  await page.evaluate(() => {
    const b = document.createElement("button");
    b.id = "kbd-start";
    b.textContent = "start";
    b.style.outline = "2px solid black";
    b.addEventListener("blur", () => b.remove(), { once: true });
    document.body.prepend(b);
    b.focus();
  });
}

async function navTo(page: Page, name: string, heading: string | RegExp) {
  await fromTop(page);
  await tabTo(page, page.getByRole("navigation", { name: "Views" }).getByRole("link", { name }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
}

test("console actions complete with the keyboard alone and every intermediate state passes axe", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-2.23", "FR-7.10");
  test.setTimeout(600_000);
  tabKey = browserName === "webkit" ? "Alt+Tab" : "Tab";
  states = 0;
  await page.emulateMedia({ reducedMotion: "reduce" });

  // Sign in.
  await page.goto(g.adminURL + "/");
  await axe(page, "sign-in");
  await tabTo(page, page.getByLabel("Password"));
  await page.keyboard.type(g.adminPassword);
  await axe(page, "sign-in filled");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
  await axe(page, "G-01 signed in");

  // G-11: create a Session Approver, then remove it through its dialog.
  await navTo(page, "Sessions and principals", "Sessions and principals");
  const user = `kbd-${browserName}`;
  const form = page.getByRole("form", { name: "Add a Session Approver" });
  await tabTo(page, form.getByLabel("Username"));
  await page.keyboard.type(user);
  await page.keyboard.press("Tab");
  await page.keyboard.type("keyboard-approver-pw");
  await page.keyboard.press("Tab");
  await page.keyboard.type("keyboard-approver-px");
  await expect(form.getByRole("alert")).toContainText("differ");
  await axe(page, "G-11 approver passwords differ");
  await page.keyboard.press("Backspace");
  await page.keyboard.type("w");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Created Session Approver ${user}.`)).toBeVisible();
  await expect(page.getByRole("table", { name: "Session Approver accounts" })).toContainText(user);
  await axe(page, "G-11 approver created");
  await tabTo(page, page.getByRole("button", { name: `Remove ${user}` }));
  await page.keyboard.press("Enter");
  const rm = page.getByRole("dialog", { name: `Remove Session Approver ${user}` });
  await expect(rm).toBeVisible();
  await axe(page, "G-11 remove dialog");
  // Escape closes the dialog: no keyboard trap.
  await page.keyboard.press("Escape");
  await expect(rm).toBeHidden();
  await tabTo(page, page.getByRole("button", { name: `Remove ${user}` }));
  await page.keyboard.press("Enter");
  await expect(rm).toBeVisible();
  await page.keyboard.type("keyboard test");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Removed Session Approver ${user}.`)).toBeVisible();
  await expect(page.getByRole("table", { name: "Session Approver accounts" })).not.toContainText(user);
  await axe(page, "G-11 approver removed");

  // G-11: create a principal, suspend it and enable it again.
  const pid = `kbd-agent-${browserName}`;
  const add = page.getByRole("form", { name: "Add a principal" });
  await tabTo(page, add.getByLabel("Principal ID"));
  await page.keyboard.type(pid);
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Created principal ${pid}.`)).toBeVisible();
  await axe(page, "G-11 principal created");
  await tabTo(page, page.getByRole("button", { name: `Suspend ${pid}` }));
  await page.keyboard.press("Enter");
  const sus = page.getByRole("dialog", { name: `Suspend principal ${pid}` });
  await expect(sus).toBeVisible();
  await axe(page, "G-11 suspend dialog");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Suspended principal ${pid}.`)).toBeVisible();
  await axe(page, "G-11 principal suspended");
  await tabTo(page, page.getByRole("button", { name: `Enable ${pid}` }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: `Enable principal ${pid}` })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Enabled principal ${pid}.`)).toBeVisible();

  // G-01: emergency stop and resume.
  await navTo(page, "Gateway control", "Gateway control");
  const strip = page.getByTestId("status-strip");
  await fromTop(page);
  await tabTo(page, page.getByTestId("emergency-button"));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "Emergency stop" })).toBeVisible();
  await axe(page, "G-01 stop dialog");
  await page.keyboard.type("keyboard acceptance test");
  await page.keyboard.press("Enter");
  await expect(strip).toContainText("emergency stop", { timeout: 2_000 });
  await axe(page, "G-01 stopped");
  await fromTop(page);
  await tabTo(page, page.getByTestId("emergency-button"));
  await page.keyboard.press("Enter");
  const resume = page.getByRole("dialog", { name: "Resume the Gateway" });
  await expect(resume).toBeVisible();
  await axe(page, "G-01 resume dialog");
  await tabTo(page, resume.getByRole("button", { name: "Resume the Gateway" }));
  await page.keyboard.press("Enter");
  await expect(strip).not.toContainText("emergency stop", { timeout: 2_000 });
  await axe(page, "G-01 resumed");

  // G-02: validate a draft and diff it against the active revision.
  await navTo(page, "Policy studio", /Policy studio/);
  await tabTo(page, page.getByRole("link", { name: "Draft", exact: true }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Session Allow templates" })).toBeVisible();
  await axe(page, "G-02 draft");
  await tabTo(page, page.getByRole("button", { name: "Validate", exact: true }));
  await page.keyboard.press("Enter");
  await expect(page.getByText(/^Valid: revision/)).toBeVisible();
  await page.keyboard.press(tabKey);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: /^Diff against/ })).toBeVisible();
  await axe(page, "G-02 validated and diffed");

  // G-10: enroll a trust anchor after its fingerprint, then remove it.
  await navTo(page, "Servers and library", "Servers and library");
  await tabTo(page, page.getByRole("link", { name: "Library and trust anchors" }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Library and trust anchors" })).toBeVisible();
  const prefix = join(work, `kbd-anchor-${browserName}-${Date.now()}`);
  const keyID = execFileSync(join(bin, "smcpctl"), ["package", "keygen", "--out", prefix, "--unencrypted"], { encoding: "utf8" }).match(/^key (\S+)/m)![1]!;
  const enroll = page.getByText("Enroll a trust anchor");
  await tabTo(page, page.locator("summary", { hasText: "Enroll a trust anchor" }));
  await page.keyboard.press("Enter");
  const ef = page.getByRole("form", { name: "Enroll a trust anchor" });
  await expect(enroll).toBeVisible();
  await tabTo(page, ef.getByLabel("Anchor name"));
  await page.keyboard.type(`kbd-${browserName}`);
  await page.keyboard.press("Tab");
  await page.keyboard.type(readFileSync(prefix + ".pub", "utf8").trim());
  await axe(page, "G-10 enroll form filled");
  await tabTo(page, ef.getByRole("button", { name: "Show fingerprint" }));
  await page.keyboard.press("Enter");
  await expect(ef.getByRole("status", { name: "Key fingerprint" })).toContainText(keyID);
  await axe(page, "G-10 fingerprint shown");
  await tabTo(page, ef.getByLabel("The key ID matches the publisher's"));
  await page.keyboard.press("Space");
  await expect(ef.getByLabel("The key ID matches the publisher's")).toBeChecked();
  await tabTo(page, ef.getByRole("button", { name: "Enroll anchor" }));
  await page.keyboard.press("Enter");
  const anchors = page.getByRole("table", { name: "Trust anchors" });
  await expect(anchors).toContainText(`kbd-${browserName}`);
  await axe(page, "G-10 anchor enrolled");
  await tabTo(page, page.getByRole("button", { name: `Remove kbd-${browserName}` }));
  await page.keyboard.press("Enter");
  await expect(anchors).not.toContainText(`kbd-${browserName}`);
  await axe(page, "G-10 anchor removed");

  // Sign out with the keyboard.
  await fromTop(page);
  await tabTo(page, page.getByRole("button", { name: "Sign out" }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await axe(page, "signed out");
  forget("administrator");
  console.log(`keyboard flows (${browserName}): ${states} states passed axe`);
});
