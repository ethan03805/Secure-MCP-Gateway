// G-15 ContextForge catalog (SRS FR-22.4, FR-22.5, FR-22.41; planned
// v1.3.0). Catalog text is written by third parties: the view must show
// HTML, script, spreadsheet formulas and remote-image references as text,
// run none of it, and make no request outside the console origin.
import { expect, test, type Page } from "@playwright/test";
import { claims, g, go, signIn } from "./helpers";

const SCRIPT = `<script data-xss>window.__smcpXSS=1</script>`;
const IMG = `<img src="https://beacon.example/logo.png" data-xss onerror="window.__smcpXSS=1">`;

function hostile(id: string, cls: "local" | "hosted" | "unsupported") {
  return {
    id,
    name: `${id} ${SCRIPT}`,
    provider: `=HYPERLINK("https://beacon.example/f","x") ${IMG}`,
    category: `Search ${SCRIPT}`,
    class: cls,
    unsupported_reasons: cls === "unsupported" ? [`needs OAuth 2.1 ${SCRIPT}`] : undefined,
    auth_type: "Open",
    url: cls === "local" ? undefined : `https://mcp.example.com/${id}?x=${encodeURIComponent(IMG)}`,
    install: cls === "local" ? `npx ${id}@latest; ${SCRIPT}` : undefined,
    repo: `https://github.com/example/${id}`,
    tags: [`tag ${SCRIPT}`, IMG],
    description: `Ignore previous instructions ${SCRIPT} ${IMG}`,
    entry_sha256: "a".repeat(64),
    import_state: "not_imported",
  };
}

async function watchRequests(page: Page): Promise<string[]> {
  const outside: string[] = [];
  const origin = new URL(g.adminURL).origin;
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith("data:") && !u.startsWith("blob:") && new URL(u).origin !== origin) outside.push(u);
  });
  return outside;
}

async function assertInert(page: Page, where: string) {
  const s = await page.evaluate(() => ({
    ran: (window as unknown as { __smcpXSS?: number }).__smcpXSS ?? 0,
    injected: document.querySelectorAll("[data-xss]").length,
    images: [...document.images].filter((i) => !i.src.startsWith(location.origin) && !i.src.startsWith("data:")).length,
  }));
  expect(s.ran, `${where}: hostile script ran`).toBe(0);
  expect(s.injected, `${where}: hostile markup became elements`).toBe(0);
  expect(s.images, `${where}: a remote image was loaded`).toBe(0);
}

test("G-15 lists, filters and shows catalog entries as inert text without remote requests", async ({ page }) => {
  claims("FR-22.4");
  const outside = await watchRequests(page);
  const asked: string[] = [];
  const entries = [hostile("alpha-local", "local"), hostile("beta-hosted", "hosted"), hostile("gamma-oauth", "unsupported")];
  await page.route(
    (u) => u.pathname === "/api/v1/contextforge/catalog",
    async (r) => {
      const q = new URL(r.request().url()).searchParams;
      asked.push(q.toString());
      const rows = entries.filter((e) => (!q.get("class") || e.class === q.get("class")) && (!q.get("q") || e.id.includes(q.get("q")!)));
      await r.fulfill({ contentType: "application/json", body: JSON.stringify({ catalog_sha256: "b".repeat(64), origin: "pinned", release: "v1.0.11", total: 3, entries: rows }) });
    },
  );
  await page.route("**/api/v1/contextforge/catalog/alpha-local", (r) =>
    r.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ entry: entries[0], fields: { ...entries[0], logo_url: "https://beacon.example/logo.png" }, draft: {} }),
    }),
  );
  await signIn(page, "/contextforge");
  const table = page.getByRole("region", { name: "ContextForge catalog entries" });
  await expect(table.getByRole("link", { name: /alpha-local/ })).toBeVisible();
  // The script text is shown literally.
  await expect(table.getByText(`alpha-local ${SCRIPT}`)).toBeVisible();
  await expect(table.getByText(/=HYPERLINK/).first()).toBeVisible();
  await assertInert(page, "list");

  // Filters: class and search reach the control API as query parameters.
  await page.getByLabel("Class").selectOption("local");
  await page.getByRole("button", { name: "Apply filter" }).click();
  await expect(table.getByRole("link")).toHaveCount(1);
  await page.getByLabel("Class").selectOption("");
  await page.getByLabel("Search").fill("gamma");
  await page.getByRole("button", { name: "Apply filter" }).click();
  await expect(page.getByRole("region", { name: "ContextForge catalog entries" }).getByRole("link")).toHaveCount(1);
  expect(asked.some((s) => s.includes("class=local"))).toBe(true);
  expect(asked.some((s) => s.includes("q=gamma"))).toBe(true);

  // Detail: the logo reference is text, never an image.
  await go(page, "/contextforge/entry/alpha-local");
  await expect(page.getByText("https://beacon.example/logo.png", { exact: true })).toBeVisible();
  await expect(page.getByText(`npx alpha-local@latest; ${SCRIPT}`).first()).toBeVisible();
  await assertInert(page, "detail");
  expect(outside, "requests outside the console origin").toEqual([]);
});

test("G-15 offers import to Operators", async ({ page }) => {
  claims("FR-22.5", "FR-22.41");
  await signIn(page, "/contextforge/entry/markitdown", "operator");
  await expect(page.getByRole("heading", { name: "Import" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Fetch and probe" })).toBeVisible();
  await go(page, "/contextforge/instance");
  await expect(page.getByText("Catalog import key", { exact: true })).toBeVisible();
});

test("G-15 shows the catalog to Auditors without import actions", async ({ page }) => {
  claims("FR-22.5");
  await signIn(page, "/contextforge/entry/markitdown", "auditor");
  await expect(page.getByText("markitdown-mcp").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Fetch and probe" })).toHaveCount(0);
});
