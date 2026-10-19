// The Check for Updates window's model (FR-20.11 to FR-20.13, FR-20.46 to
// FR-20.48): what it offers in each state and the catalogue text it shows.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fill, plan, PREVIEWS, shown, type MessageCatalogue, type UpdatesView } from "../src/updates-model.ts";

const catalogue = JSON.parse(readFileSync(new URL("../../docs/design/messages.json", import.meta.url), "utf8")) as MessageCatalogue;

const base: UpdatesView = { phase: "idle", installed: "1.3.0", appNewer: false, notes: false, gatewayUpgradable: false, log: [] };

test("placeholders are filled from the parameters", () => {
  assert.equal(fill("version {version} of {x}", { version: "1.4.0" }), "version 1.4.0 of {x}");
  const m = shown(catalogue, "errors", "UPDATE_NOT_NEWER", { offered: "1.2.0", installed: "1.3.0" });
  assert.match(m.what, /version 1\.2\.0, is not newer than the installed version 1\.3\.0/);
  assert.throws(() => shown(catalogue, "errors", "NO_SUCH_CODE", {}));
});

test("FR-20.11: a newer release is reported with its version and notes", () => {
  const p = plan(catalogue, PREVIEWS.available!);
  assert.equal(p.status, "Version 1.4.0 is available. This app is version 1.3.0. The Gateway is version 1.3.0.");
  assert.ok(p.canOpenNotes && p.appUpdate && p.gatewayUpgrade);
  assert.deepEqual(p.facts, [["This app", "1.3.0"], ["Gateway", "1.3.0"], ["Newest release", "1.4.0"]]);
});

test("FR-20.46: the latest version shows the catalogue's empty state", () => {
  const p = plan(catalogue, PREVIEWS.latest!);
  assert.equal(p.message?.code, "UPDATES_NONE");
  assert.equal(p.message?.what, "Version 1.3.0 is the newest stable release.");
  assert.equal(p.isError, false);
  assert.ok(!p.appUpdate && !p.gatewayUpgrade && !p.canOpenNotes);
});

test("FR-20.47: each update error is the catalogue's text with its code and details", () => {
  for (const name of ["verify-failed", "rolled-back", "offline"]) {
    const v = PREVIEWS[name]!;
    const p = plan(catalogue, v);
    assert.ok(p.isError, name);
    assert.equal(p.message?.code, v.message?.code, name);
    assert.equal(p.message?.details, v.message?.details, name);
    assert.ok(p.message?.title && p.message.what && p.message.todo, name);
    assert.doesNotMatch(JSON.stringify(p.message), /\{[a-z]+\}/, `${name}: an unfilled placeholder`);
  }
  assert.equal(plan(catalogue, PREVIEWS["verify-failed"]!).message?.what, "The downloaded release did not pass the SHA-256 checksum check.");
  // FR-20.12: a rollback is a failed upgrade with the version running afterwards.
  assert.match(plan(catalogue, PREVIEWS["rolled-back"]!).message?.what ?? "", /restored version 1\.3\.0, which is running now/);
  // The upgrade can be tried again after a rollback.
  assert.ok(plan(catalogue, PREVIEWS["rolled-back"]!).gatewayUpgrade);
});

test("busy states offer no second operation", () => {
  const p = plan(catalogue, PREVIEWS.working!);
  assert.ok(p.busy && !p.canCheck && !p.canOpenNotes && !p.appUpdate && !p.gatewayUpgrade);
  assert.ok(plan(catalogue, { ...base, phase: "checking" }).busy);
});

test("FR-20.13: an app not installed from a release installer says why it is not updated", () => {
  const p = plan(catalogue, { ...PREVIEWS.available!, appKind: null, appBlocked: "not from an installer" });
  assert.equal(p.appUpdate, false);
  assert.equal(p.appBlocked, "not from an installer");
  const q = plan(catalogue, { ...PREVIEWS.available!, gatewayUpgradable: false, gatewayBlocked: "Enforced" });
  assert.equal(q.gatewayUpgrade, false);
  assert.equal(q.gatewayBlocked, "Enforced");
  // A Gateway already on the newest version is not offered an upgrade.
  assert.equal(plan(catalogue, { ...PREVIEWS.available!, gateway: "1.4.0" }).gatewayUpgrade, false);
});

test("every desktop error code the Rust side raises for updates is in the catalogue", () => {
  const src = readFileSync(new URL("../src-tauri/src/updates.rs", import.meta.url), "utf8");
  const codes = new Set([...src.matchAll(/"((?:UPDATE|UPGRADE)_[A-Z_]+)"/g)].map((m) => m[1]!));
  assert.ok(codes.size >= 5, [...codes].join(","));
  for (const c of codes) assert.ok(catalogue.desktop.errors[c], `${c} is not in docs/design/messages.json`);
});
