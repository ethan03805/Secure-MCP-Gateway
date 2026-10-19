import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { errorsByField, fromValues, toFieldErrors } from "../src/form.ts";

test("form values become the settings the Rust side stores", () => {
  const s = fromValues({ admin_url: " https://127.0.0.1:8444 ", metrics_address: "127.0.0.1:9464\n", ca_file: "" }, false);
  assert.deepEqual(s, { admin_url: "https://127.0.0.1:8444", metrics_address: "127.0.0.1:9464", ca_file: "", notifications: false });
});

test("validation errors land on their fields", () => {
  const e = errorsByField([
    { field: "admin_url", message: "the admin listener is served over HTTPS only (CP-03)" },
    { field: "metrics_address", message: "a" },
    { field: "metrics_address", message: "b" },
    { field: "file", message: "disk full" },
  ]);
  assert.equal(e.admin_url, "the admin listener is served over HTTPS only (CP-03)");
  assert.equal(e.metrics_address, "a b");
  assert.equal(e.ca_file, "");
  assert.equal(e.form, "disk full");
});

test("rejections of any shape become field errors", () => {
  assert.deepEqual(toFieldErrors("not allowed from this window"), [{ field: "form", message: "not allowed from this window" }]);
  assert.deepEqual(toFieldErrors([{ field: "ca_file", message: "give an absolute path" }, { bogus: 1 }]), [
    { field: "ca_file", message: "give an absolute path" },
  ]);
  assert.equal(toFieldErrors(undefined)[0]?.field, "form");
});

// SR-2-6: bundled pages reference packaged files only; the settings page
// loads its script from 'self' and has no inline script or handler.
test("bundled pages load nothing remote and nothing inline", () => {
  for (const page of ["settings.html", "error.html"]) {
    const html = readFileSync(new URL(`../src/${page}`, import.meta.url), "utf8");
    assert.doesNotMatch(html, /https?:\/\//, `${page} names a remote URL`);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, `${page} has an inline script`);
    assert.doesNotMatch(html, /\son[a-z]+=/i, `${page} has an inline event handler`);
  }
  const settings = readFileSync(new URL("../src/settings.html", import.meta.url), "utf8");
  assert.match(settings, /<script type="module" src="settings.js"><\/script>/);
});

// SR-2-5: the page calls only the commands its capability grants.
test("the settings page calls only get_settings and save_settings", () => {
  const src = readFileSync(new URL("../src/settings.ts", import.meta.url), "utf8");
  const calls = [...src.matchAll(/invoke<[^>]*>\("([a-z_]+)"/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(calls)].sort(), ["get_settings", "save_settings"]);
  const cap = JSON.parse(readFileSync(new URL("../src-tauri/capabilities/settings.json", import.meta.url), "utf8"));
  assert.deepEqual(cap.permissions, ["allow-get-settings", "allow-save-settings"]);
});
