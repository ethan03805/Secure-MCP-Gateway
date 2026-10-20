// The bundled IBM Plex faces (docs/design/visual.md, Type; src/fonts/README.md):
// the four files are the recorded ones, their licenses ship beside them, the
// windows' stylesheet uses them first and nothing is loaded from elsewhere.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

const dir = new URL("../src/fonts/", import.meta.url);
const read = (f: string) => readFileSync(new URL(f, dir));

const SUMS: Record<string, string> = {
  "ibm-plex-sans-latin-400-normal.woff2": "3b646991d30055a93a4ecc499713d4347953a74a947ecab435ab72070cbdab0e",
  "ibm-plex-sans-latin-600-normal.woff2": "8960851d691c054ed38e259bdcf1a6190d157b4203ed5bb32c632a863fb8ec2f",
  "ibm-plex-mono-latin-400-normal.woff2": "08949f728dc52d528e69b1667d15c89a5686a4ee9a296ff90983985f99c380f7",
  "ibm-plex-mono-latin-500-normal.woff2": "01d285447409c8a588692162439a038b8cbd7871309ee20267b0d2d91c6e8e22",
};

test("the four bundled faces are the recorded files", () => {
  const woff2 = readdirSync(dir).filter((f) => f.endsWith(".woff2")).sort();
  assert.deepEqual(woff2, Object.keys(SUMS).sort());
  for (const [f, sum] of Object.entries(SUMS)) {
    const b = read(f);
    assert.equal(b.subarray(0, 4).toString("latin1"), "wOF2", f);
    assert.equal(createHash("sha256").update(b).digest("hex"), sum, f);
  }
});

test("the OFL license of each family ships with the faces", () => {
  const licenses: [string, string][] = [
    ["OFL-IBM-Plex-Sans.txt", "IBMPlexSans"],
    ["OFL-IBM-Plex-Mono.txt", "IBMPlexMono"],
  ];
  for (const [f, family] of licenses) {
    const t = read(f).toString("utf8");
    assert.match(t, /SIL Open Font License, Version 1\.1/, f);
    assert.match(t, new RegExp(`${family}.*Copyright \\d{4} IBM Corp`), f);
  }
});

test("plex.css declares every face from the bundle and nothing remote", () => {
  const css = read("plex.css").toString("utf8");
  for (const f of Object.keys(SUMS)) assert.match(css, new RegExp(`url\\(${f.replaceAll(".", "\\.")}\\)`), f);
  assert.doesNotMatch(css, /https?:|\/\//);
  const faces = [...css.matchAll(/font-family: "([^"]+)";\s*font-style: normal;\s*font-weight: (\d+);/g)].map((m) => `${m[1]} ${m[2]}`);
  assert.deepEqual(faces.sort(), ["IBM Plex Mono 400", "IBM Plex Mono 500", "IBM Plex Sans 400", "IBM Plex Sans 600"]);
});

test("the windows' stylesheet imports the bundle and names Plex first", () => {
  const css = readFileSync(new URL("../src/style.css", import.meta.url), "utf8");
  assert.match(css, /@import url\("fonts\/plex\.css"\);/);
  assert.match(css, /--sans: "IBM Plex Sans",/);
  assert.match(css, /--mono: "IBM Plex Mono",/);
  assert.doesNotMatch(css, /fonts\.googleapis|fonts\.gstatic|https?:\/\//);
});
