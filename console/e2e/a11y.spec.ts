// Automated WCAG 2.2 A/AA checks (axe-core) of every view in light and
// dark color schemes. Automated checks find only part of the failures WCAG
// covers, so this is a partial claim of FR-8.32; keyboard operation is
// exercised in console.spec.ts.
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { info } from "./gateway";

const g = info();
const paths = [
  "/",
  "/sessions",
  "/servers",
  "/servers/ref",
  "/catalog",
  "/approvals",
  "/audit",
  "/policy",
  "/secrets",
  "/observations",
  "/analytics",
  "/performance",
  "/data-server",
  "/research",
  "/audit-profiles",
  "/anomaly-response",
  "/egress",
  "/runtime",
  "/remote",
];

for (const scheme of ["light", "dark"] as const) {
  test(`views have no WCAG 2.2 AA violations found by axe (${scheme})`, async ({ page }) => {
    test.info().annotations.push({ type: "requirement-partial", description: "FR-8.32" });
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.goto(g.adminURL + "/");
    const signin = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    expect(signin.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    await page.getByLabel("Password").fill(g.adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
    for (const p of paths) {
      await page.evaluate((to) => {
        history.pushState(null, "", to);
        dispatchEvent(new PopStateEvent("popstate"));
      }, p);
      await expect(page.locator(".loading")).toHaveCount(0);
      const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
      expect(r.violations.map((v) => `${p} ${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    }
  });
}
