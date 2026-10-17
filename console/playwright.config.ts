import { defineConfig, devices } from "@playwright/test";

// Acceptance tests against a real smcpd started by e2e/global-setup.ts.
// The admin listener uses the Gateway's local CA, which the browser does
// not trust, hence ignoreHTTPSErrors.
export default defineConfig({
  testDir: "e2e",
  testMatch: "*.spec.ts",
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 180_000,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
